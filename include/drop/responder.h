/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_RESPONDER_H
#define HAVE_DROP_RESPONDER_H

#include <drop/stun.h>
#include <drop/types.h>

#include <samurai/io/net/datagram.h>
#include <samurai/io/net/serversocket.h>
#include <samurai/io/net/socket.h>
#include <samurai/io/net/socketevent.h>

#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Drop {

/**
 * Answers the DROP challenge on a TCP port.
 *
 * A DC client would fold this into the client-to-client listener it already
 * has rather than opening a second one, demultiplexing on the first bytes:
 *
 *     "CSUP"        ADC client-to-client, plaintext
 *     0x16 0x03     TLS ClientHello (ADCS)
 *     "DROP/1 "     a DROP challenge
 *
 * A port that otherwise accepts only TLS must still take the plaintext
 * challenge: recognising a seven-byte prefix before the handshake is trivial,
 * and requiring TLS for a single-use nonce exchange buys nothing.
 *
 * handleChallenge() is public so that a client which has its own listener can
 * use the protocol without this class at all.
 */
class TcpResponder final
	: public Samurai::IO::Net::ServerSocketEventHandler
	, public Samurai::IO::Net::SocketEventHandler
{
	public:
		/** @param loop the loop it listens on, which must outlive it. */
		explicit TcpResponder(Samurai::EventLoop& loop);
		~TcpResponder() override;

		TcpResponder(const TcpResponder&) = delete;
		TcpResponder& operator=(const TcpResponder&) = delete;

		/**
		 * Bind and listen.
		 *
		 * @param bindAddress the address to listen on, or empty for any.
		 * @param port zero for an ephemeral one, which getPort() then reports.
		 */
		bool listen(Family family, const std::string& bindAddress, uint16_t port);

		uint16_t getPort() const { return port; }
		void close();

		/** How many challenges have been answered, for tests and diagnostics. */
		int getAnswered() const { return answered; }

		/**
		 * The most a challenge line can be.
		 *
		 * Here rather than inside the implementation because a client sharing its
		 * own listener has to size the buffer it demultiplexes on: a line is
		 * recognised by its prefix but answered by echoing the nonce inside it, so
		 * a buffer that holds only enough to recognise one cannot answer it, and
		 * the port then looks closed to every check that ever probes it.
		 */
		static constexpr size_t MaxChallenge = 128;

		/**
		 * Turn a challenge line into its response.
		 *
		 * @param line at most MaxChallenge bytes of it, terminator optional.
		 * @return false when the line is not a DROP challenge, in which case the
		 *         bytes belong to whatever else shares the port.
		 */
		static bool handleChallenge(std::string_view line, std::string& response);

	private:
		void EventAcceptError(const Samurai::IO::Net::ServerSocket*, const char*) override;
		void EventAcceptSocket(const Samurai::IO::Net::ServerSocket*,
		                       std::shared_ptr<Samurai::IO::Net::Socket>) override;

		void EventDataAvailable(const Samurai::IO::Net::Socket*) override;
		void EventDisconnected(const Samurai::IO::Net::Socket*) override;
		void EventError(const Samurai::IO::Net::Socket*,
		                Samurai::IO::Net::SocketError, const char*) override;

		void forget(const Samurai::IO::Net::Socket* socket);

		Samurai::EventLoop& loop;
		std::shared_ptr<Samurai::IO::Net::ServerSocket> server;
		/** Held until each has answered or gone away. */
		std::vector<std::shared_ptr<Samurai::IO::Net::Socket>> accepted;
		uint16_t port = 0;
		int answered = 0;
};

/**
 * Answer a DROP UDP probe from a datagram the caller already read.
 *
 * This is the entry point for an ADC client, which must run the responder on
 * the very socket it advertises in U4/U6 - testing any other socket measures a
 * different port than the one that matters. Call it from the existing read
 * loop; anything it declines belongs to the application sharing the socket,
 * which for a DC client is its own UDP search results.
 *
 * Silence is the answer to everything unauthenticated, which is why this
 * reports "nothing to send" rather than an error to return. A reply to a
 * datagram whose source was never proven is a reflection an attacker can aim
 * anywhere, so a probe that fails MESSAGE-INTEGRITY gets nothing at all.
 *
 * @param datagram what was received, whole.
 * @param username the session's STUN username, empty when no session is open,
 *        in which case nothing is ever answered.
 * @param password the session's STUN password.
 * @param from where the datagram came from, which the reply reports back as
 *        the client's reflexive address.
 * @param reply filled with the bytes to send back to 'from'.
 * @return true when 'reply' should be sent. False means send nothing, and
 *         does not distinguish "not for us" from "refused" - the caller
 *         should pass a declined datagram to whatever else uses the socket.
 */
bool handleStunProbe(std::span<const uint8_t> datagram,
                     std::string_view username, std::string_view password,
                     const Stun::Endpoint& from,
                     std::vector<uint8_t>& reply);

/**
 * Answers authenticated STUN Binding Requests on a UDP port.
 *
 * MUST run on the very socket the client advertises in U4/U6, or the test
 * measures a different port than the one that matters.
 *
 * The credential check is not optional politeness. Without it every client
 * becomes an open STUN responder that an attacker can aim anywhere with a
 * spoofed source address, so a request whose MESSAGE-INTEGRITY does not verify
 * against a session opened moments ago is met with silence.
 */
class UdpResponder final : public Samurai::IO::Net::DatagramEventHandler
{
	public:
		/** @param loop the loop it listens on, which must outlive it. */
		explicit UdpResponder(Samurai::EventLoop& loop);
		~UdpResponder() override;

		UdpResponder(const UdpResponder&) = delete;
		UdpResponder& operator=(const UdpResponder&) = delete;

		bool listen(Family family, const std::string& bindAddress, uint16_t port);

		uint16_t getPort() const { return port; }
		void close();

		/**
		 * The credentials to accept, from the session just opened.
		 *
		 * Clearing them stops the responder answering anything, which is what a
		 * client should do once its inbound test has finished.
		 */
		void setCredentials(std::string username, std::string password);
		void clearCredentials();

		int getAnswered() const { return answered; }
		/** Requests seen but refused, which is what a scan looks like. */
		int getRefused() const { return refused; }

		/** The socket, so behaviour discovery can share it if a caller wants. */
		std::shared_ptr<Samurai::IO::Net::DatagramSocket> getSocket() const
		{ return socket; }

	private:
		void EventGotDatagram(Samurai::IO::Net::DatagramSocket*,
		                      Samurai::IO::Net::DatagramPacket*) override;
		void EventDatagramError(const Samurai::IO::Net::DatagramSocket*,
		                        const char* msg) override;

		Samurai::EventLoop& loop;
		std::shared_ptr<Samurai::IO::Net::DatagramSocket> socket;
		std::string username;
		std::string password;
		uint16_t port = 0;
		int answered = 0;
		int refused = 0;

		/** Answers per second, so a flood cannot be amplified through us. */
		int budget = 0;
		int64_t budgetSecond = 0;
		bool withinBudget();
};

}

#endif // HAVE_DROP_RESPONDER_H
