/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/responder.h>

#include "hmac.h"

#include <samurai/io/net/socketaddress.h>

#include <string.h>
#include <time.h>

using Samurai::IO::Net::DatagramPacket;
using Samurai::IO::Net::DatagramSocket;
using Samurai::IO::Net::InetAddress;
using Samurai::IO::Net::InetSocketAddress;
using Samurai::IO::Net::ServerSocket;
using Samurai::IO::Net::Socket;

namespace Drop {

namespace {

constexpr const char* CHALLENGE_PREFIX = "DROP/1 CHALLENGE ";
constexpr const char* RESPONSE_PREFIX  = "DROP/1 RESPONSE ";

/**
 * The line cap the protocol fixes.
 *
 * Both sides enforce it and neither reads further, so a peer that never sends
 * a newline cannot make the other buffer. Taken from the published constant
 * rather than restated, so that a client sizing its own buffer from the header
 * and this reader cannot disagree about the bound.
 */
constexpr size_t MAX_LINE = TcpResponder::MaxChallenge;

/** Answers per second, above which a flood is dropped rather than reflected. */
constexpr int ANSWERS_PER_SECOND = 20;

InetAddress anyAddressFor(Family family, const std::string& bindAddress)
{
	if (!bindAddress.empty())
		return InetAddress(bindAddress);
	return InetAddress(family == Family::IPv6 ? "::" : "0.0.0.0");
}

int64_t nowSeconds()
{
	timespec ts{};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<int64_t>(ts.tv_sec);
}

} // namespace

/* --- TcpResponder -------------------------------------------------------- */

TcpResponder::TcpResponder() = default;

TcpResponder::~TcpResponder()
{
	close();
}

bool TcpResponder::handleChallenge(std::string_view line, std::string& response)
{
	/* Trim the terminator, whichever spelling arrived. */
	while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
		line.remove_suffix(1);

	if (line.size() > MAX_LINE)
		return false;

	const std::string_view prefix(CHALLENGE_PREFIX);
	if (line.size() <= prefix.size() || line.compare(0, prefix.size(), prefix) != 0)
		return false;

	const std::string_view nonce = line.substr(prefix.size());
	if (nonce.empty())
		return false;

	/*
	 * The nonce is echoed as it arrived. The specification makes matching it
	 * against a recent session a SHOULD rather than a MUST here, unlike the UDP
	 * rule: this peer completed a TCP handshake, so its address is proven and
	 * there is nothing to reflect, and the answer is the same size as the
	 * question. A client that wants to track recent nonces can do so around
	 * this call.
	 */
	response.assign(RESPONSE_PREFIX);
	response.append(nonce);
	response.push_back('\n');
	return true;
}

bool TcpResponder::listen(Family family, const std::string& bindAddress, uint16_t port)
{
	close();

	const InetSocketAddress addr(anyAddressFor(family, bindAddress), port);
	server = ServerSocket::create(this, addr);
	if (!server || server->getFD() == -1)
	{
		server.reset();
		return false;
	}
	if (!server->listen())
	{
		server.reset();
		return false;
	}

	this->port = server->getLocalPort();
	return this->port != 0;
}

void TcpResponder::close()
{
	accepted.clear();
	server.reset();
	port = 0;
}

void TcpResponder::EventAcceptError(const ServerSocket*, const char*)
{
}

void TcpResponder::EventAcceptSocket(const ServerSocket*,
                                     std::shared_ptr<Socket> socket)
{
	if (!socket)
		return;

	/*
	 * A probe is one line each way and then a close, so a connection that
	 * lingers is not one. Holding an unbounded number of them would be a way
	 * to exhaust this process's descriptors from outside.
	 */
	if (accepted.size() >= 16)
		accepted.erase(accepted.begin());

	socket->setEventHandler(this);
	accepted.push_back(socket);
}

void TcpResponder::forget(const Socket* socket)
{
	for (size_t i = 0; i < accepted.size(); i++)
	{
		if (accepted[i].get() == socket)
		{
			accepted[i]->setEventHandler(nullptr);
			accepted.erase(accepted.begin() + static_cast<long>(i));
			return;
		}
	}
}

void TcpResponder::EventDataAvailable(const Socket* which)
{
	Socket* socket = const_cast<Socket*>(which);

	/* Never more than the line cap, so a peer sending endlessly is bounded. */
	char scratch[MAX_LINE + 1];
	size_t got = 0;
	std::error_code ec;
	if (socket->read(scratch, MAX_LINE, got, ec) != Samurai::IO::ReadResult::Ok)
	{
		forget(which);
		return;
	}

	std::string response;
	if (handleChallenge(std::string_view(scratch, got), response))
	{
		socket->write(response.data(), response.size(), ec);
		answered++;
	}

	/* One exchange per connection either way: anything that was not a
	   challenge is not ours to interpret. */
	forget(which);
}

void TcpResponder::EventDisconnected(const Socket* which)
{
	forget(which);
}

void TcpResponder::EventError(const Socket* which, Samurai::IO::Net::SocketError,
                              const char*)
{
	forget(which);
}

/* --- UdpResponder -------------------------------------------------------- */

UdpResponder::UdpResponder() = default;

UdpResponder::~UdpResponder()
{
	close();
}

bool UdpResponder::listen(Family family, const std::string& bindAddress, uint16_t port)
{
	close();

	const InetSocketAddress addr(anyAddressFor(family, bindAddress), port);
	socket = DatagramSocket::create(this, addr);
	if (!socket || socket->getFD() == -1)
	{
		socket.reset();
		return false;
	}
	if (!socket->listen())
	{
		socket.reset();
		return false;
	}

	this->port = socket->getLocalPort();
	return this->port != 0;
}

void UdpResponder::close()
{
	if (socket) socket->setEventHandler(nullptr);
	socket.reset();
	port = 0;
	clearCredentials();
}

void UdpResponder::setCredentials(std::string user, std::string pass)
{
	username = std::move(user);
	password = std::move(pass);
}

void UdpResponder::clearCredentials()
{
	username.clear();
	password.clear();
}

bool UdpResponder::withinBudget()
{
	const int64_t second = nowSeconds();
	if (second != budgetSecond)
	{
		budgetSecond = second;
		budget = 0;
	}
	return ++budget <= ANSWERS_PER_SECOND;
}

/*
 * The protocol, with no socket in it. UdpResponder is a thin wrapper that owns
 * a socket and calls this; an ADC client calls it directly from the read loop
 * of the socket it already advertises.
 */
bool handleStunProbe(std::span<const uint8_t> datagram,
                     std::string_view username, std::string_view password,
                     const Stun::Endpoint& from,
                     std::vector<uint8_t>& reply)
{
	reply.clear();

	/*
	 * Demultiplex. Anything that is not STUN belongs to whatever application
	 * shares this socket - for a DC client, its ADC UDP search results, which
	 * begin with an ASCII letter and so can never look like STUN.
	 */
	if (!Stun::Message::looksLikeStun(datagram))
		return false;

	Stun::Message request;
	if (!Stun::Message::decode(datagram, request))
		return false;
	if (request.type != Stun::BINDING_REQUEST)
		return false;   /* answering a response would let two agents ping-pong */
	if (!request.checkFingerprint())
		return false;

	/*
	 * Everything below is met with silence rather than an error. An error is
	 * still a reply, and a reply to a spoofed source is exactly the reflection
	 * this rule exists to prevent.
	 */
	if (password.empty())
		return false;

	const std::optional<std::string> user = request.getUsername();
	if (!user || *user != username)
		return false;

	const std::span<const uint8_t> key(
		reinterpret_cast<const uint8_t*>(password.data()), password.size());
	if (!request.checkMessageIntegrity(key))
		return false;

	if (!from.valid())
		return false;

	Stun::Message response = Stun::Message::response(request);
	response.addAddress(Stun::Attr::XorMappedAddress, from, true);
	response.addMessageIntegritySha256(key);
	response.addMessageIntegrity(key);
	response.addFingerprint();

	reply = response.encode();
	return true;
}

void UdpResponder::EventGotDatagram(DatagramSocket* from, DatagramPacket* packet)
{
	if (!from || !packet)
		return;

	uint8_t buf[1500];
	const int got = packet->read(buf, sizeof(buf));
	if (got <= 0)
		return;

	Samurai::IO::Net::SocketAddress* peer = packet->getAddress();
	if (!peer)
		return;

	/* Only an internet address has an address and a port to read back; the
	   base class is deliberately transport-agnostic. */
	InetSocketAddress* inet = dynamic_cast<InetSocketAddress*>(peer);
	if (!inet)
		return;

	const InetAddress* peerAddress = inet->getAddress();
	if (!peerAddress)
		return;

	const std::optional<Stun::Endpoint> reflexive =
		Stun::parseEndpoint(peerAddress->toString(), inet->getPort());
	if (!reflexive)
		return;

	/* Counted before the budget so that a scan is visible in getRefused()
	   even when the answer is withheld. */
	const bool wasStun =
		Stun::Message::looksLikeStun(std::span<const uint8_t>(buf, (size_t) got));

	std::vector<uint8_t> reply;
	if (!handleStunProbe(std::span<const uint8_t>(buf, (size_t) got),
	                     username, password, *reflexive, reply))
	{
		if (wasStun)
			refused++;
		return;
	}

	if (!withinBudget())
		return;

	DatagramPacket out(reply.data(), reply.size());
	out.setAddress(peer);
	from->send(&out);
	answered++;
}

void UdpResponder::EventDatagramError(const DatagramSocket*, const char*)
{
}

}
