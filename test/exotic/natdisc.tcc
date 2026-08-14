/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/natdisc.h>
#include <drop/stun.h>

#include "pump.h"

#include <samurai/io/net/datagram.h>
#include <samurai/io/net/socketaddress.h>
#include <samurai/io/net/socketevent.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

/*
 * RFC 5780 classification, against a server on the loopback interface.
 *
 * The trick that makes this testable without a NAT: the client classifies by
 * comparing the XOR-MAPPED-ADDRESS it gets back across three requests, so a
 * server that simply *reports* chosen addresses drives every branch of the
 * tree. A NAT is only a thing that makes those three answers differ, and here
 * the server does that directly.
 *
 * The whole of 127/8 is local on Linux, so 127.0.0.1 and 127.0.0.2 give the
 * two addresses RFC 5780 needs. Where the platform has only one, the cases
 * skip rather than fail.
 */

namespace {

using namespace Drop;
using Samurai::IO::Net::DatagramPacket;
using Samurai::IO::Net::DatagramSocket;
using Samurai::IO::Net::InetAddress;
using Samurai::IO::Net::InetSocketAddress;

/** Which of the four sockets a request arrived on, or should leave from. */
enum class Role { Primary, AltAddr, AltPort, AltBoth };

/**
 * A STUN server with the four endpoints behaviour discovery needs, and a dial
 * for each of the ways a real one disappoints a client.
 */
class FakeServer final : public Samurai::IO::Net::DatagramEventHandler
{
	public:
		/* What to report as the client's mapped address, per endpoint. A NAT
		   is modelled entirely by making these differ. */
		std::map<Role, std::string> mappedAddress;
		uint16_t mappedPort = 40000;

		/** Without this a client cannot classify anything. */
		bool advertiseOtherAddress = true;
		/** The half of RFC 5780 that deployed servers usually lack. */
		bool honourChangeRequest = true;
		/** Refuse it explicitly, rather than ignoring it. */
		bool refuseChangeRequest = false;
		/** Answer nothing at all. */
		bool silent = false;

		bool start()
		{
			if (!bindOne(Role::Primary, "127.0.0.1")) return false;
			if (!bindOne(Role::AltAddr, "127.0.0.2")) return false;
			if (!bindOne(Role::AltPort, "127.0.0.1")) return false;
			if (!bindOne(Role::AltBoth, "127.0.0.2")) return false;

			/*
			 * The client derives Test II's target as (other.address,
			 * primary.port), so the alternate address must answer on the
			 * primary's port number too. Two independently bound ephemeral
			 * ports would leave that target dead and the run would report
			 * "no reply from the alternate address" instead of classifying.
			 */
			return rebindAlternateToPrimaryPort();
		}

		~FakeServer() override
		{
			for (auto& [role, socket] : sockets)
			{
				(void) role;
				if (socket) socket->setEventHandler(nullptr);
			}
		}

		Stun::Endpoint primary() const { return endpointOf(Role::Primary); }

		Stun::Endpoint endpointOf(Role role) const
		{
			const auto it = ports.find(role);
			const auto addr = addresses.find(role);
			Stun::Endpoint e;
			if (it != ports.end() && addr != addresses.end())
			{
				e.address = addr->second;
				e.port = it->second;
			}
			return e;
		}

		int requests = 0;

	protected:
		void EventGotDatagram(DatagramSocket* on, DatagramPacket* packet) override
		{
			if (silent) return;

			uint8_t buf[1500];
			const int got = packet->read(buf, sizeof(buf));
			if (got <= 0) return;

			const std::span<const uint8_t> datagram(buf, (size_t) got);
			if (!Stun::Message::looksLikeStun(datagram)) return;

			Stun::Message request;
			if (!Stun::Message::decode(datagram, request)) return;
			if (request.type != Stun::BINDING_REQUEST) return;

			requests++;

			const Role arrivedOn = roleOf(on);

			uint32_t flags = 0;
			if (const std::optional<uint32_t> change = request.getChangeRequest())
				flags = *change;

			Role answerFrom = arrivedOn;
			if (flags)
			{
				if (refuseChangeRequest || !honourChangeRequest)
				{
					if (refuseChangeRequest)
					{
						Stun::Message error = Stun::Message::error(
							request, Stun::CODE_BAD_REQUEST, "no CHANGE-REQUEST");
						sendFrom(arrivedOn, error, packet->getAddress());
					}
					/* Ignoring it is the other real behaviour: no reply at
					   all, which is indistinguishable from a NAT dropping. */
					return;
				}
				answerFrom = shift(arrivedOn, flags);
			}

			Stun::Message response = Stun::Message::response(request);

			Stun::Endpoint mapped;
			mapped.address = mappedAddress.count(arrivedOn)
				? mappedAddress.at(arrivedOn) : std::string("203.0.113.1");
			mapped.port = mappedPort;
			response.addAddress(Stun::Attr::XorMappedAddress, mapped, true);

			response.addAddress(Stun::Attr::ResponseOrigin,
			                    endpointOf(answerFrom), false);
			if (advertiseOtherAddress)
				response.addAddress(Stun::Attr::OtherAddress,
				                    endpointOf(Role::AltBoth), false);
			response.addFingerprint();

			sendFrom(answerFrom, response, packet->getAddress());
		}

		void EventDatagramError(const DatagramSocket*, const char*) override { }

	private:
		bool bindOne(Role role, const char* address)
		{
			const InetSocketAddress addr(InetAddress(address), (uint16_t) 0);
			auto socket = DatagramSocket::create(this, addr);
			if (!socket || socket->getFD() == -1 || !socket->listen())
				return false;

			ports[role] = socket->getLocalPort();
			addresses[role] = address;
			sockets[role] = socket;
			return true;
		}

		/** Give the alternate address a socket on the primary's port number. */
		bool rebindAlternateToPrimaryPort()
		{
			const uint16_t wanted = ports[Role::Primary];
			const InetSocketAddress addr(InetAddress("127.0.0.2"), wanted);

			auto socket = DatagramSocket::create(this, addr);
			if (!socket || socket->getFD() == -1 || !socket->listen())
				return false;   /* the port is taken on that address */

			sockets[Role::AltAddr] = socket;
			ports[Role::AltAddr] = wanted;
			return true;
		}

		Role roleOf(DatagramSocket* socket) const
		{
			for (const auto& [role, held] : sockets)
			{
				if (held.get() == socket)
					return role;
			}
			return Role::Primary;
		}

		/** Which endpoint a CHANGE-REQUEST asks to answer from. */
		static Role shift(Role from, uint32_t flags)
		{
			const bool changeIp = (flags & Stun::CHANGE_IP) != 0;
			const bool changePort = (flags & Stun::CHANGE_PORT) != 0;

			bool altAddr = (from == Role::AltAddr || from == Role::AltBoth);
			bool altPort = (from == Role::AltPort || from == Role::AltBoth);
			if (changeIp) altAddr = !altAddr;
			if (changePort) altPort = !altPort;

			if (altAddr && altPort) return Role::AltBoth;
			if (altAddr)            return Role::AltAddr;
			if (altPort)            return Role::AltPort;
			return Role::Primary;
		}

		void sendFrom(Role role, const Stun::Message& message,
		              Samurai::IO::Net::SocketAddress* to)
		{
			const auto it = sockets.find(role);
			if (it == sockets.end() || !it->second || !to)
				return;
			const std::vector<uint8_t> wire = message.encode();
			DatagramPacket packet(wire.data(), wire.size());
			packet.setAddress(to);
			it->second->send(&packet);
		}

		std::map<Role, std::shared_ptr<DatagramSocket>> sockets;
		std::map<Role, uint16_t> ports;
		std::map<Role, std::string> addresses;
};

/** Whether this machine offers 127.0.0.2 as a second local address. */
bool haveSecondLoopback()
{
	const InetSocketAddress addr(InetAddress("127.0.0.2"), (uint16_t) 0);
	auto probe = DatagramSocket::create(nullptr, addr);
	return probe && probe->getFD() != -1;
}

NatDiscovery::Options optionsFor(const FakeServer& server)
{
	NatDiscovery::Options options;
	options.primary = server.primary();
	options.localAddress = "127.0.0.1";
	options.timeout = std::chrono::milliseconds(700);
	return options;
}

} // namespace

EXO_TEST(natdisc_no_nat_when_the_mapped_address_is_our_own, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	/* Reporting the client's own address is what "nothing is translating"
	   looks like from the client's side. */
	server.mappedAddress[Role::Primary] = "127.0.0.1";
	server.mappedAddress[Role::AltAddr] = "127.0.0.1";
	server.mappedAddress[Role::AltBoth] = "127.0.0.1";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	return result.mapping == Behaviour::None
	    && result.filtering == Behaviour::EndpointIndependent;
});

EXO_TEST(natdisc_endpoint_independent_mapping, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	/* One external address whatever the destination: the friendly NAT. */
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedAddress[Role::AltAddr] = "203.0.113.7";
	server.mappedAddress[Role::AltBoth] = "203.0.113.7";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	return result.mapping == Behaviour::EndpointIndependent
	    && result.holePunchLikely();
});

EXO_TEST(natdisc_address_dependent_mapping, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	/* A different mapping for the alternate address, but the same one for
	   both of its ports: the mapping depends on the address alone. */
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedAddress[Role::AltAddr] = "203.0.113.8";
	server.mappedAddress[Role::AltBoth] = "203.0.113.8";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	return result.mapping == Behaviour::AddressDependent
	    /* Endpoint-independent mapping is the precondition for hole
	       punching, and this is not it. */
	    && !result.holePunchLikely();
});

EXO_TEST(natdisc_address_and_port_dependent_mapping, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	/* A fresh mapping per destination port as well: the hostile case. */
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedAddress[Role::AltAddr] = "203.0.113.8";
	server.mappedAddress[Role::AltBoth] = "203.0.113.9";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	return result.mapping == Behaviour::AddressAndPortDependent
	    && !result.holePunchLikely();
});

EXO_TEST(natdisc_reports_blocked_when_nothing_answers, {
	FakeServer server;
	server.silent = true;
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	/*
	 * With the control plane working, silence from the primary endpoint means
	 * outbound UDP does not leave this network - so search results can never
	 * work, whatever else is arranged.
	 */
	return result.mapping == Behaviour::Blocked
	    && result.filtering == Behaviour::Blocked
	    && !result.notes.empty();
});

EXO_TEST(natdisc_without_other_address_classifies_nothing, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	server.advertiseOtherAddress = false;
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	/* Most public STUN servers are this server. Saying so is the useful
	   outcome; guessing is not. */
	return result.mapping == Behaviour::Unknown
	    && !result.notes.empty()
	    && !result.mappedAddress.empty();   /* the reflexive address still works */
});

EXO_TEST(natdisc_a_refused_change_request_is_unknown_not_restrictive, {
	/*
	 * The case that matters most. A server which cannot answer from another
	 * address is indistinguishable, from here, from the most restrictive NAT
	 * there is - and reporting the restrictive one sends users chasing a
	 * firewall problem they do not have.
	 */
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	server.refuseChangeRequest = true;
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedAddress[Role::AltAddr] = "203.0.113.7";
	server.mappedAddress[Role::AltBoth] = "203.0.113.7";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	if (result.filtering == Behaviour::AddressAndPortDependent)
		return false;
	return result.filtering == Behaviour::Unknown
	    /* And the mapping half, which does not need CHANGE-REQUEST, still
	       classified. */
	    && result.mapping == Behaviour::EndpointIndependent;
});

EXO_TEST(natdisc_endpoint_independent_filtering, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	server.honourChangeRequest = true;
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedAddress[Role::AltAddr] = "203.0.113.7";
	server.mappedAddress[Role::AltBoth] = "203.0.113.7";
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));

	/* Loopback admits the reply from the changed address, which is what an
	   endpoint-independent filter does. */
	return result.filtering == Behaviour::EndpointIndependent;
});

EXO_TEST(natdisc_refuses_an_alternate_that_is_not_different, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	if (!server.start()) return true;

	NatDiscovery::Options options = optionsFor(server);
	/*
	 * Point the client at the alternate socket as though it were the primary.
	 * OTHER-ADDRESS then names the same address the client already contacted,
	 * so nothing can be distinguished and trusting it would produce a
	 * confident wrong answer.
	 */
	options.primary = server.endpointOf(Role::AltBoth);

	const NatResult result = NatDiscovery::discover(options);

	return result.mapping == Behaviour::Unknown && !result.notes.empty();
});

EXO_TEST(natdisc_reports_port_preservation, {
	if (!haveSecondLoopback()) return true;

	FakeServer server;
	server.mappedAddress[Role::Primary] = "203.0.113.7";
	server.mappedPort = 12345;   /* not the client's local port */
	if (!server.start()) return true;

	const NatResult result = NatDiscovery::discover(optionsFor(server));
	if (result.portPreserving)
		return false;

	return !result.mappedAddress.empty()
	    && result.mappedAddress.find("12345") != std::string::npos;
});

EXO_TEST(natdisc_notes_an_unpinned_source_address, {
	/*
	 * Not fatal - a single-homed host is unaffected - but on a host with
	 * several addresses of one family it is the difference between a
	 * measurement and a coin toss, so it is said out loud.
	 */
	FakeServer server;
	server.silent = true;
	if (!server.start()) return true;

	NatDiscovery::Options options = optionsFor(server);
	options.localAddress.clear();

	const NatResult result = NatDiscovery::discover(options);

	bool warned = false;
	for (const std::string& note : result.notes)
	{
		if (note.find("source address") != std::string::npos)
			warned = true;
	}
	return warned;
});

EXO_TEST(natdisc_without_an_endpoint_does_nothing, {
	NatDiscovery::Options options;   /* no primary endpoint at all */
	const NatResult result = NatDiscovery::discover(options);

	return result.mapping == Behaviour::Unknown
	    && result.filtering == Behaviour::Unknown
	    && !result.notes.empty();
});
