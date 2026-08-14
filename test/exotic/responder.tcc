/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/responder.h>
#include <drop/stun.h>

#include "pump.h"

#include <samurai/io/net/datagram.h>
#include <samurai/io/net/socket.h>
#include <samurai/io/net/socketaddress.h>
#include <samurai/io/net/socketevent.h>
#include <samurai/io/net/socketmonitor.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <string.h>

/*
 * The responders are what a DROP server connects back to, so these stand one
 * up on the loopback interface and drive it with a real socket. Deterministic
 * on any machine and reaching no network.
 *
 * The security cases matter more than the happy path. A UDP responder that
 * answers an unauthenticated datagram is an open reflector an attacker can aim
 * anywhere with a spoofed source address, so most of what follows asserts
 * silence rather than a reply.
 */

namespace {

using namespace Drop;
using Samurai::IO::Net::DatagramPacket;
using Samurai::IO::Net::DatagramSocket;
using Samurai::IO::Net::InetAddress;
using Samurai::IO::Net::InetSocketAddress;
using Samurai::IO::Net::Socket;

std::span<const uint8_t> keyOf(const std::string& text)
{
	return std::span<const uint8_t>(
		reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

/** A client that sends one line and collects whatever comes back. */
class LineClient final : public Samurai::IO::Net::SocketEventHandler
{
	public:
		std::string received;
		bool finished = false;
		bool connected = false;

		bool exchange(uint16_t port, const std::string& line,
		              std::chrono::milliseconds timeout = std::chrono::seconds(3))
		{
			toSend = line;
			socket = Socket::create(this, "127.0.0.1", port);
			if (!socket) return false;
			socket->setConnectTimeout(timeout);
			socket->connect();

			pump([&] { return finished; }, timeout);

			socket->setEventHandler(nullptr);
			socket->disableMonitor();
			socket.reset();
			return connected;
		}

	protected:
		void EventConnected(const Socket* which) override
		{
			connected = true;
			std::error_code ec;
			const_cast<Socket*>(which)->write(toSend.data(), toSend.size(), ec);
		}

		void EventDataAvailable(const Socket* which) override
		{
			char buf[256];
			size_t got = 0;
			std::error_code ec;
			if (const_cast<Socket*>(which)->read(buf, sizeof(buf), got, ec)
			    != Samurai::IO::ReadResult::Ok)
			{
				finished = true;
				return;
			}
			received.append(buf, got);
			finished = true;
		}

		void EventDisconnected(const Socket*) override { finished = true; }
		void EventTimeout(const Socket*) override { finished = true; }
		void EventError(const Socket*, Samurai::IO::Net::SocketError,
		                const char*) override { finished = true; }

	private:
		std::shared_ptr<Socket> socket;
		std::string toSend;
};

/** Sends one datagram and collects a reply, if any comes. */
class DatagramClient final : public Samurai::IO::Net::DatagramEventHandler
{
	public:
		std::vector<uint8_t> received;
		bool answered = false;

		bool send(uint16_t port, const std::vector<uint8_t>& payload,
		          std::chrono::milliseconds wait = std::chrono::milliseconds(600))
		{
			InetSocketAddress any(InetAddress("127.0.0.1"), (uint16_t) 0);
			socket = DatagramSocket::create(this, any);
			if (!socket || socket->getFD() == -1) return false;
			if (!socket->listen()) return false;

			InetSocketAddress to(InetAddress("127.0.0.1"), port);
			DatagramPacket packet(payload.data(), payload.size());
			packet.setAddress(&to);
			socket->send(&packet);

			pump([&] { return answered; }, wait);

			socket->setEventHandler(nullptr);
			socket.reset();
			return true;
		}

	protected:
		void EventGotDatagram(DatagramSocket*, DatagramPacket* packet) override
		{
			uint8_t buf[1500];
			const int got = packet->read(buf, sizeof(buf));
			if (got > 0)
				received.assign(buf, buf + got);
			answered = true;
		}

		void EventDatagramError(const DatagramSocket*, const char*) override { }

	private:
		std::shared_ptr<DatagramSocket> socket;
};

Stun::TxId someTxId()
{
	Stun::TxId id{};
	Stun::newTxId(id);
	return id;
}

} // namespace

/* --- the challenge, as pure logic ---------------------------------------- */

EXO_TEST(challenge_answers_a_well_formed_line, {
	std::string response;
	if (!TcpResponder::handleChallenge("DROP/1 CHALLENGE abc123\n", response))
		return false;
	return response == "DROP/1 RESPONSE abc123\n";
});

EXO_TEST(challenge_accepts_either_line_ending, {
	std::string a;
	std::string b;
	std::string c;
	return TcpResponder::handleChallenge("DROP/1 CHALLENGE x\n", a)
	    && TcpResponder::handleChallenge("DROP/1 CHALLENGE x\r\n", b)
	    && TcpResponder::handleChallenge("DROP/1 CHALLENGE x", c)  /* unterminated */
	    && a == b && b == c;
});

EXO_TEST(challenge_ignores_everything_that_is_not_one, {
	/*
	 * The port is shared with ADC and with TLS, so anything that is not a
	 * challenge belongs to another protocol and must be left alone.
	 */
	const char* others[] = {
		"CSUP ADBAS0 ADTIGR\n",          /* ADC client-to-client */
		"\x16\x03\x01\x00\x50",          /* a TLS ClientHello */
		"DROP/1 RESPONSE abc\n",         /* our own response, not a challenge */
		"DROP/2 CHALLENGE abc\n",        /* a version this does not speak */
		"DROP/1 CHALLENGE\n",            /* no nonce */
		"DROP/1 CHALLENGE \n",           /* an empty nonce */
		"",
		"\n",
	};

	for (const char* text : others)
	{
		std::string response;
		if (TcpResponder::handleChallenge(text, response))
			return false;
	}
	return true;
});

EXO_TEST(challenge_refuses_an_overlong_line, {
	/* Both sides enforce the 128-byte cap, so a peer that never sends a
	   newline cannot make the other buffer. */
	std::string line = "DROP/1 CHALLENGE ";
	line.append(200, 'A');

	std::string response;
	return !TcpResponder::handleChallenge(line, response);
});

/* --- the TCP responder on a real socket ---------------------------------- */

EXO_TEST(tcp_responder_answers_a_challenge, {
	TcpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	if (responder.getPort() == 0) return false;

	LineClient client;
	if (!client.exchange(responder.getPort(), "DROP/1 CHALLENGE nonce-value\n"))
		return false;

	return client.received == "DROP/1 RESPONSE nonce-value\n"
	    && responder.getAnswered() == 1;
});

EXO_TEST(tcp_responder_says_nothing_to_another_protocol, {
	TcpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;

	LineClient client;
	client.exchange(responder.getPort(), "CSUP ADBAS0 ADTIGR\n");

	return client.received.empty() && responder.getAnswered() == 0;
});

EXO_TEST(tcp_responder_survives_a_flood_on_one_connection, {
	TcpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;

	std::string flood(64 * 1024, 'x');
	LineClient noisy;
	noisy.exchange(responder.getPort(), flood);

	/* And still serves the next caller. */
	LineClient good;
	good.exchange(responder.getPort(), "DROP/1 CHALLENGE after-flood\n");

	return good.received == "DROP/1 RESPONSE after-flood\n";
});

EXO_TEST(tcp_responder_handles_several_connections, {
	TcpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;

	for (int i = 0; i < 5; i++)
	{
		LineClient client;
		const std::string nonce = "nonce" + std::to_string(i);
		if (!client.exchange(responder.getPort(), "DROP/1 CHALLENGE " + nonce + "\n"))
			return false;
		if (client.received != "DROP/1 RESPONSE " + nonce + "\n")
			return false;
	}
	return responder.getAnswered() == 5;
});

EXO_TEST(tcp_responder_can_be_closed_and_reopened, {
	TcpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	const uint16_t first = responder.getPort();

	responder.close();
	if (responder.getPort() != 0) return false;

	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	return responder.getPort() != 0 && responder.getPort() != first;
});

/* --- the UDP responder --------------------------------------------------- */

EXO_TEST(udp_responder_answers_an_authenticated_probe, {
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	Stun::Message probe = Stun::Message::request(someTxId());
	probe.addString(Stun::Attr::Username, "session-id");
	probe.addUint32(Stun::Attr::DropProbe, responder.getPort());
	probe.addMessageIntegritySha256(keyOf("session-password"));
	probe.addMessageIntegrity(keyOf("session-password"));
	probe.addFingerprint();

	DatagramClient client;
	if (!client.send(responder.getPort(), probe.encode())) return false;
	if (!client.answered) return false;

	Stun::Message response;
	if (!Stun::Message::decode(
	        std::span<const uint8_t>(client.received.data(), client.received.size()),
	        response))
		return false;

	return response.type == Stun::BINDING_RESPONSE
	    && response.txid == probe.txid
	    /* The answer is authenticated too, or the prober cannot tell it from
	       an off-path forgery. */
	    && response.checkMessageIntegrity(keyOf("session-password"))
	    && response.getAddress(Stun::Attr::XorMappedAddress, true).has_value()
	    && responder.getAnswered() == 1;
});

EXO_TEST(udp_responder_is_silent_without_credentials, {
	/*
	 * Silence rather than an error: an error is still a reply, and a reply to
	 * a spoofed source is exactly the reflection this rule prevents.
	 */
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	/* No credentials set, which is a client that has no session open. */

	Stun::Message probe = Stun::Message::request(someTxId());
	probe.addString(Stun::Attr::Username, "session-id");
	probe.addMessageIntegrity(keyOf("session-password"));
	probe.addFingerprint();

	DatagramClient client;
	client.send(responder.getPort(), probe.encode());

	return !client.answered
	    && responder.getAnswered() == 0
	    && responder.getRefused() == 1;
});

EXO_TEST(udp_responder_refuses_a_wrong_key_or_username, {
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	{   /* right username, wrong key */
		Stun::Message probe = Stun::Message::request(someTxId());
		probe.addString(Stun::Attr::Username, "session-id");
		probe.addMessageIntegrity(keyOf("the-wrong-password"));
		probe.addFingerprint();

		DatagramClient client;
		client.send(responder.getPort(), probe.encode());
		if (client.answered) return false;
	}
	{   /* right key, wrong username */
		Stun::Message probe = Stun::Message::request(someTxId());
		probe.addString(Stun::Attr::Username, "somebody-else");
		probe.addMessageIntegrity(keyOf("session-password"));
		probe.addFingerprint();

		DatagramClient client;
		client.send(responder.getPort(), probe.encode());
		if (client.answered) return false;
	}
	{   /* no credentials at all: an ordinary STUN client would answer this */
		Stun::Message probe = Stun::Message::request(someTxId());
		probe.addFingerprint();

		DatagramClient client;
		client.send(responder.getPort(), probe.encode());
		if (client.answered) return false;
	}

	return responder.getAnswered() == 0 && responder.getRefused() >= 3;
});

EXO_TEST(udp_responder_ignores_what_is_not_stun, {
	/*
	 * The socket is shared with ADC search results, which must reach the
	 * application rather than being consumed or answered here.
	 */
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	const char* adc = "URES IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KCII SI1 SL3\n";
	std::vector<uint8_t> datagram(adc, adc + strlen(adc));

	DatagramClient client;
	client.send(responder.getPort(), datagram);

	return !client.answered
	    && responder.getAnswered() == 0
	    /* Not even counted as refused: it was never addressed to us. */
	    && responder.getRefused() == 0;
});

EXO_TEST(udp_responder_ignores_a_response_rather_than_ping_ponging, {
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	/* A Binding Response, not a request. Answering one would let two agents
	   trade datagrams forever. */
	Stun::Message notARequest =
		Stun::Message::response(Stun::Message::request(someTxId()));
	notARequest.addMessageIntegrity(keyOf("session-password"));

	DatagramClient client;
	client.send(responder.getPort(), notARequest.encode());

	return !client.answered && responder.getAnswered() == 0;
});

EXO_TEST(udp_responder_stops_when_credentials_are_cleared, {
	/* What a client does once its check is finished: keeping the responder
	   answering is running a service nobody asked for. */
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	Stun::Message probe = Stun::Message::request(someTxId());
	probe.addString(Stun::Attr::Username, "session-id");
	probe.addMessageIntegrity(keyOf("session-password"));
	probe.addFingerprint();
	const std::vector<uint8_t> wire = probe.encode();

	DatagramClient before;
	before.send(responder.getPort(), wire);
	if (!before.answered) return false;

	responder.clearCredentials();

	/* A fresh transaction, since the responder is not asked to remember. */
	Stun::Message again = Stun::Message::request(someTxId());
	again.addString(Stun::Attr::Username, "session-id");
	again.addMessageIntegrity(keyOf("session-password"));
	again.addFingerprint();

	DatagramClient after;
	after.send(responder.getPort(), again.encode());

	return !after.answered;
});

EXO_TEST(udp_responder_survives_garbage, {
	UdpResponder responder;
	if (!responder.listen(Family::IPv4, "127.0.0.1", 0)) return false;
	responder.setCredentials("session-id", "session-password");

	const std::vector<std::vector<uint8_t>> junk = {
		{},
		{ 0x00 },
		std::vector<uint8_t>(19, 0),
		std::vector<uint8_t>(1400, 0xFF),
		{ 0x00, 0x01, 0xFF, 0xFF, 0x21, 0x12, 0xA4, 0x42 },  /* absurd length */
	};

	for (const std::vector<uint8_t>& datagram : junk)
	{
		DatagramClient client;
		client.send(responder.getPort(), datagram,
		            std::chrono::milliseconds(150));
		if (client.answered) return false;
	}

	/* And a real probe still works afterwards. */
	Stun::Message probe = Stun::Message::request(someTxId());
	probe.addString(Stun::Attr::Username, "session-id");
	probe.addMessageIntegrity(keyOf("session-password"));
	probe.addFingerprint();

	DatagramClient good;
	good.send(responder.getPort(), probe.encode());
	return good.answered;
});

/* --- the UDP protocol without a socket ----------------------------------- */

/*
 * This is the path an ADC client takes: it already owns the socket it
 * advertises in U4/U6, and must run the responder on that one, because testing
 * any other socket measures a different port than the one that matters.
 */

EXO_TEST(handle_stun_probe_answers_an_authenticated_request, {
	Stun::Message probe = Stun::Message::request(someTxId());
	probe.addString(Stun::Attr::Username, "session-id");
	probe.addMessageIntegrity(keyOf("session-password"));
	probe.addFingerprint();
	const std::vector<uint8_t> wire = probe.encode();

	const std::optional<Stun::Endpoint> from =
		Stun::parseEndpoint("203.0.113.7", 51343);
	if (!from) return false;

	std::vector<uint8_t> reply;
	if (!handleStunProbe(std::span<const uint8_t>(wire.data(), wire.size()),
	                     "session-id", "session-password", *from, reply))
		return false;

	Stun::Message response;
	if (!Stun::Message::decode(
	        std::span<const uint8_t>(reply.data(), reply.size()), response))
		return false;

	const std::optional<Stun::Endpoint> mapped =
		response.getAddress(Stun::Attr::XorMappedAddress, true);

	return response.type == Stun::BINDING_RESPONSE
	    && response.txid == probe.txid
	    && response.checkMessageIntegrity(keyOf("session-password"))
	    && response.checkFingerprint()
	    /* The reflexive address handed back is the one the caller observed. */
	    && mapped && *mapped == *from;
});

EXO_TEST(handle_stun_probe_declines_everything_it_should, {
	const std::optional<Stun::Endpoint> from =
		Stun::parseEndpoint("203.0.113.7", 51343);
	if (!from) return false;

	auto declines = [&](const std::vector<uint8_t>& datagram,
	                    const char* user, const char* pass) {
		std::vector<uint8_t> reply;
		const bool answered = handleStunProbe(
			std::span<const uint8_t>(datagram.data(), datagram.size()),
			user, pass, *from, reply);
		/* A declined datagram must leave nothing to send. */
		return !answered && reply.empty();
	};

	/* ADC search results, which must reach the application untouched. */
	const char* adc = "URES IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KCII SI1\n";
	if (!declines(std::vector<uint8_t>(adc, adc + strlen(adc)),
	              "session-id", "session-password"))
		return false;

	Stun::Message good = Stun::Message::request(someTxId());
	good.addString(Stun::Attr::Username, "session-id");
	good.addMessageIntegrity(keyOf("session-password"));
	good.addFingerprint();

	/* No session open: a client that is not being checked answers nobody. */
	if (!declines(good.encode(), "", "")) return false;
	/* Wrong key, and wrong username. */
	if (!declines(good.encode(), "session-id", "wrong-password")) return false;
	if (!declines(good.encode(), "somebody-else", "session-password")) return false;

	/* Unauthenticated, which an ordinary STUN server would answer. */
	Stun::Message anonymous = Stun::Message::request(someTxId());
	anonymous.addFingerprint();
	if (!declines(anonymous.encode(), "session-id", "session-password"))
		return false;

	/* A response rather than a request. */
	Stun::Message response =
		Stun::Message::response(Stun::Message::request(someTxId()));
	response.addMessageIntegrity(keyOf("session-password"));
	if (!declines(response.encode(), "session-id", "session-password"))
		return false;

	return declines({}, "session-id", "session-password");
});
