/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/natdisc.h>

#include "pump.h"

#include <samurai/io/net/datagram.h>
#include <samurai/io/net/socketaddress.h>
#include <samurai/io/net/socketevent.h>

#include <memory>
#include <vector>

using Samurai::IO::Net::DatagramPacket;
using Samurai::IO::Net::DatagramSocket;
using Samurai::IO::Net::InetAddress;
using Samurai::IO::Net::InetSocketAddress;

namespace Drop {

namespace {

/** Why a request produced no usable answer. */
enum class Outcome
{
	Ok,
	/** Nothing came back within the deadline. */
	Silent,
	/** The server refused the CHANGE-REQUEST, which is not the same thing. */
	ChangeUnsupported,
	/** An error response, or the socket could not be used. */
	Failed
};

/**
 * One socket, and the requests sent from it.
 *
 * Responses are matched by transaction id and deliberately not by source
 * address: the filtering tests exist precisely to see whether a reply arrives
 * from an address the client never wrote to.
 */
class Transactor final : public Samurai::IO::Net::DatagramEventHandler
{
	public:
		Transactor(const std::string& bindAddress, bool wantIPv6)
		{
			const InetAddress local(bindAddress.empty()
				? (wantIPv6 ? "::" : "0.0.0.0")
				: bindAddress);
			const InetSocketAddress addr(local, (uint16_t) 0);

			socket = DatagramSocket::create(this, addr);
			if (socket && socket->getFD() != -1 && socket->listen())
				port = socket->getLocalPort();
			else
				socket.reset();
		}

		~Transactor() override
		{
			if (socket) socket->setEventHandler(nullptr);
		}

		bool usable() const { return socket != nullptr; }
		uint16_t getPort() const { return port; }

		Outcome request(const Stun::Endpoint& to, uint32_t changeFlags,
		                const std::string& username, const std::string& password,
		                std::chrono::milliseconds timeout,
		                Stun::Message& out, Stun::Endpoint& from)
		{
			if (!socket)
				return Outcome::Failed;

			if (!Stun::newTxId(pending))
				return Outcome::Failed;

			Stun::Message request = Stun::Message::request(pending);
			if (changeFlags)
				request.addUint32(Stun::Attr::ChangeRequest, changeFlags);
			if (!username.empty())
			{
				const std::span<const uint8_t> key(
					reinterpret_cast<const uint8_t*>(password.data()),
					password.size());
				request.addString(Stun::Attr::Username, username);
				request.addMessageIntegritySha256(key);
				request.addMessageIntegrity(key);
			}
			request.addFingerprint();

			const std::vector<uint8_t> wire = request.encode();
			expectedPassword = password;

			answered = false;
			errored = false;
			errorCode = 0;

			/*
			 * Retransmit rather than conclude from one datagram. UDP loss on a
			 * consumer path is low but not zero, and the failure it produces
			 * here is the expensive kind: a lost reply to Test II reads as
			 * restrictive filtering, which sends the user to reconfigure a
			 * firewall that was working.
			 */
			const std::chrono::milliseconds attempts[] = {
				std::chrono::milliseconds(0),
				std::chrono::milliseconds(300),
				std::chrono::milliseconds(900),
			};

			const auto start = std::chrono::steady_clock::now();
			const auto deadline = start + timeout;
			size_t next = 0;

			while (std::chrono::steady_clock::now() < deadline && !answered && !errored)
			{
				const auto now = std::chrono::steady_clock::now();
				if (next < 3 && now >= start + attempts[next])
				{
					send(to, wire);
					next++;
				}

				auto wake = deadline;
				if (next < 3 && start + attempts[next] < wake)
					wake = start + attempts[next];

				const auto slice = std::chrono::duration_cast<std::chrono::milliseconds>(
					wake - std::chrono::steady_clock::now());
				pump([&] { return answered || errored; },
				     slice.count() > 0 ? slice : std::chrono::milliseconds(1));
			}

			if (errored)
			{
				/*
				 * A 400 to a request that carried CHANGE-REQUEST is the
				 * server saying it cannot do that, which is a different fact
				 * from a NAT dropping the reply.
				 */
				if (changeFlags && errorCode == Stun::CODE_BAD_REQUEST)
					return Outcome::ChangeUnsupported;
				return Outcome::Failed;
			}
			if (!answered)
				return Outcome::Silent;

			out = response;
			from = responseFrom;
			return Outcome::Ok;
		}

	protected:
		void EventGotDatagram(DatagramSocket*, DatagramPacket* packet) override
		{
			uint8_t buf[1500];
			const int got = packet->read(buf, sizeof(buf));
			if (got <= 0)
				return;

			const std::span<const uint8_t> datagram(buf, (size_t) got);
			if (!Stun::Message::looksLikeStun(datagram))
				return;

			Stun::Message message;
			if (!Stun::Message::decode(datagram, message))
				return;
			if (message.txid != pending)
				return;
			if (!message.checkFingerprint())
				return;

			/* When credentials were sent, an unauthenticated answer is not
			   ours: an off-path forger cannot produce the MAC. */
			if (!expectedPassword.empty() &&
			    (message.has(Stun::Attr::MessageIntegrity) ||
			     message.has(Stun::Attr::MessageIntegritySha256)))
			{
				const std::span<const uint8_t> key(
					reinterpret_cast<const uint8_t*>(expectedPassword.data()),
					expectedPassword.size());
				if (!message.checkMessageIntegrity(key))
					return;
			}

			if (message.type == Stun::BINDING_ERROR)
			{
				std::string reason;
				message.getErrorCode(errorCode, reason);
				errored = true;
				return;
			}
			if (message.type != Stun::BINDING_RESPONSE)
				return;

			response = message;

			if (Samurai::IO::Net::SocketAddress* addr = packet->getAddress())
			{
				if (InetSocketAddress* inet =
				        dynamic_cast<InetSocketAddress*>(addr))
				{
					if (const InetAddress* a = inet->getAddress())
					{
						if (const std::optional<Stun::Endpoint> e =
						        Stun::parseEndpoint(a->toString(), inet->getPort()))
							responseFrom = *e;
					}
				}
			}

			answered = true;
		}

		void EventDatagramError(const DatagramSocket*, const char*) override
		{
			errored = true;
		}

	private:
		void send(const Stun::Endpoint& to, const std::vector<uint8_t>& wire)
		{
			InetSocketAddress dst(InetAddress(to.address), to.port);
			DatagramPacket packet(wire.data(), wire.size());
			packet.setAddress(&dst);
			socket->send(&packet);
		}

		std::shared_ptr<DatagramSocket> socket;
		uint16_t port = 0;

		Stun::TxId pending{};
		std::string expectedPassword;
		Stun::Message response;
		Stun::Endpoint responseFrom;
		bool answered = false;
		bool errored = false;
		int errorCode = 0;
};

/** The address the socket is bound to, as an endpoint for comparison. */
Stun::Endpoint localEndpoint(const std::string& address, uint16_t port, bool v6)
{
	if (const std::optional<Stun::Endpoint> e = Stun::parseEndpoint(address, port))
		return *e;

	Stun::Endpoint fallback;
	fallback.port = port;
	fallback.v6 = v6;
	return fallback;
}

const char* UNSUPPORTED_NOTE =
	"The server does not implement CHANGE-REQUEST, so filtering behaviour "
	"could not be determined. Treat it as unknown rather than restrictive: "
	"the two look identical from here.";

/**
 * RFC 5780 section 4.4, on a socket that has never sent to the alternate
 * address.
 *
 * The fresh socket is not tidiness. The mapping tests just finished sending to
 * the alternate address on purpose, and a NAT that saw that now has a mapping
 * open towards it - so it will accept the very reply Test II is designed to
 * find out whether it accepts. Reusing the socket classifies almost every NAT
 * as endpoint-independent-filtering, which for a restrictive one is exactly
 * backwards.
 */
Behaviour discoverFiltering(const NatDiscovery::Options& options, bool v6,
                            std::vector<std::string>& notes)
{
	Transactor fresh(options.localAddress, v6);
	if (!fresh.usable())
		return Behaviour::Unknown;

	Stun::Message response;
	Stun::Endpoint from;

	/* Test I establishes the mapping and confirms the path works before
	   anything unusual is asked for. */
	if (fresh.request(options.primary, 0, options.username, options.password,
	                  options.timeout, response, from) != Outcome::Ok)
		return Behaviour::Blocked;

	/* Test II: answer from a different address and port. A reply means the NAT
	   accepts traffic from endpoints this client never contacted. */
	Outcome outcome = fresh.request(options.primary,
	                                Stun::CHANGE_IP | Stun::CHANGE_PORT,
	                                options.username, options.password,
	                                options.timeout, response, from);
	if (outcome == Outcome::Ok)
		return Behaviour::EndpointIndependent;
	if (outcome == Outcome::ChangeUnsupported)
	{
		notes.push_back(UNSUPPORTED_NOTE);
		return Behaviour::Unknown;
	}

	/* Test III: a different port from the same address. */
	outcome = fresh.request(options.primary, Stun::CHANGE_PORT,
	                        options.username, options.password,
	                        options.timeout, response, from);
	if (outcome == Outcome::Ok)
		return Behaviour::AddressDependent;
	if (outcome == Outcome::ChangeUnsupported)
	{
		notes.push_back(UNSUPPORTED_NOTE);
		return Behaviour::Unknown;
	}

	return Behaviour::AddressAndPortDependent;
}

} // namespace

NatResult NatDiscovery::discover(const Options& options)
{
	NatResult result;
	result.mapping = Behaviour::Unknown;
	result.filtering = Behaviour::Unknown;

	if (!options.primary.valid())
	{
		result.notes.push_back("The server advertises no STUN endpoint for this "
		                       "address family.");
		return result;
	}

	if (options.localAddress.empty())
	{
		/*
		 * Not fatal, because a single-homed host is unaffected, but worth
		 * saying: on a host with more than one address this is the difference
		 * between a measurement and a coin toss.
		 */
		result.notes.push_back("No source address was pinned, so on a host with "
		                       "several addresses of this family the result may "
		                       "describe more than one of them.");
	}

	const bool v6 = options.primary.v6;

	Transactor mapper(options.localAddress, v6);
	if (!mapper.usable())
	{
		result.notes.push_back("A local UDP socket could not be opened.");
		return result;
	}

	const Stun::Endpoint local =
		localEndpoint(options.localAddress, mapper.getPort(), v6);
	result.localAddress = local.toString();

	/* --- RFC 5780 section 4.3, mapping ---------------------------------- */

	Stun::Message first;
	Stun::Endpoint from;
	if (mapper.request(options.primary, 0, options.username, options.password,
	                   options.timeout, first, from) != Outcome::Ok)
	{
		/*
		 * Nothing came back from the primary endpoint at all. With the control
		 * plane working, that is outbound UDP being blocked - common on
		 * corporate and campus networks, and it means UDP search results can
		 * never work whatever else is arranged.
		 */
		result.mapping = Behaviour::Blocked;
		result.filtering = Behaviour::Blocked;
		result.notes.push_back("No reply from the primary STUN endpoint, so "
		                       "outbound UDP appears to be blocked.");
		return result;
	}

	const std::optional<Stun::Endpoint> mapped =
		first.getAddress(Stun::Attr::XorMappedAddress, true);
	if (!mapped)
	{
		result.notes.push_back("The server returned no mapped address.");
		return result;
	}

	result.mappedAddress = mapped->toString();
	result.portPreserving = (mapped->port == mapper.getPort());

	if (!options.localAddress.empty() && mapped->address == options.localAddress)
	{
		/* The mapped address is our own, so nothing is translating. */
		result.mapping = Behaviour::None;
		result.filtering = discoverFiltering(options, v6, result.notes);
		return result;
	}

	const std::optional<Stun::Endpoint> other =
		first.getAddress(Stun::Attr::OtherAddress, false);
	if (!other)
	{
		result.notes.push_back("The server does not advertise OTHER-ADDRESS, so "
		                       "it cannot classify NAT behaviour. Most public "
		                       "STUN servers cannot.");
		return result;
	}

	/* A server whose alternate is not genuinely different cannot distinguish
	   anything, and trusting it produces a confident wrong answer. */
	if (other->address == options.primary.address)
	{
		result.notes.push_back("The server's OTHER-ADDRESS is not a different "
		                       "address, so behaviour discovery would be "
		                       "meaningless and was skipped.");
		return result;
	}
	result.otherAddress = other->toString();

	/* Test II: the alternate address, the primary port. */
	Stun::Endpoint secondTarget;
	secondTarget.address = other->address;
	secondTarget.port = options.primary.port;
	secondTarget.v6 = other->v6;

	Stun::Message second;
	if (mapper.request(secondTarget, 0, options.username, options.password,
	                   options.timeout, second, from) != Outcome::Ok)
	{
		result.notes.push_back("No reply from the alternate address, so mapping "
		                       "behaviour could not be classified.");
		result.filtering = discoverFiltering(options, v6, result.notes);
		return result;
	}

	const std::optional<Stun::Endpoint> secondMapped =
		second.getAddress(Stun::Attr::XorMappedAddress, true);

	if (secondMapped && *secondMapped == *mapped)
	{
		result.mapping = Behaviour::EndpointIndependent;
	}
	else
	{
		/* Test III: the alternate address and the alternate port. */
		Stun::Message third;
		if (mapper.request(*other, 0, options.username, options.password,
		                   options.timeout, third, from) != Outcome::Ok)
		{
			result.notes.push_back("No reply from the alternate address and "
			                       "port, so mapping behaviour could not be "
			                       "fully classified.");
			result.filtering = discoverFiltering(options, v6, result.notes);
			return result;
		}

		const std::optional<Stun::Endpoint> thirdMapped =
			third.getAddress(Stun::Attr::XorMappedAddress, true);

		if (secondMapped && thirdMapped && *thirdMapped == *secondMapped)
			result.mapping = Behaviour::AddressDependent;
		else
			result.mapping = Behaviour::AddressAndPortDependent;
	}

	result.filtering = discoverFiltering(options, v6, result.notes);
	return result;
}

}
