/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_CLIENT_H
#define HAVE_DROP_CLIENT_H

#include <drop/types.h>

#include <samurai/io/net/http/client.h>
#include <samurai/io/net/inetaddress.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace Drop {

class Client;

/** Implement this to receive the outcome of a control-plane request. */
class ClientEventHandler
{
	public:
		virtual ~ClientEventHandler() = default;

		virtual void EventDropServerInfo(Client*, const ServerInfo&) { }
		virtual void EventDropWhoami(Client*, const Whoami&) { }
		virtual void EventDropSession(Client*, const Session&) { }
		virtual void EventDropInbound(Client*, const InboundResult&) { }

		/** The request produced no usable answer. */
		virtual void EventDropError(Client*, const ErrorInfo&) = 0;
};

/**
 * The DROP control plane: one request at a time, asynchronously.
 *
 * Every request is HTTPS with the certificate verified and the hostname
 * checked, which Samurai's HTTP client does. Plain http is refused outright:
 * the session credentials and the probe request are the whole authorisation to
 * have an address probed, and handing them to whoever answers port 80 would
 * give that away.
 *
 * ADDRESS FAMILY: one connection has one source address, so one Client tests
 * one family. Point it at the family-specific name - ipv4.drop.example.org or
 * ipv6.drop.example.org - rather than the dual-stack one, or which family is
 * under test depends on which connection Happy Eyeballs won.
 *
 * SOURCE ADDRESS: set Options::localAddress on a host with several addresses
 * of one family. The whole measurement is about a particular address, and
 * without this the kernel picks one per destination.
 */
class Client final : public Samurai::IO::Net::HTTP::RequestEventHandler
{
	public:
		struct Options
		{
			/** Covers one request end to end. */
			std::chrono::milliseconds timeout{ 20000 };

			/**
			 * Bound to the /inbound request, which waits for the probes.
			 *
			 * The server bounds that at 15 seconds, so this has to exceed it
			 * or a client gives up on results that were about to arrive.
			 */
			std::chrono::milliseconds inboundTimeout{ 30000 };

			std::string userAgent{ "libdrop-cpp/0.1" };

			/**
			 * The address to connect from, and therefore the address the whole
			 * check is about. See the note on the class.
			 */
			std::optional<Samurai::IO::Net::InetAddress> localAddress;

			/**
			 * Accept a server certificate the trust store cannot verify.
			 *
			 * For a test deployment only. With it on, the exchange is private
			 * from a passive observer and from nobody else, and the session
			 * credentials are handed to whoever answered.
			 */
			bool allowUntrustedCertificate = false;
		};

		/**
		 * @param loop the loop every request runs on, which must outlive this.
		 * @param baseUrl the family-specific base, e.g.
		 *        "https://ipv4.drop.example.org". A trailing slash is ignored.
		 */
		Client(Samurai::EventLoop& loop, ClientEventHandler* eh, std::string baseUrl,
		       Family family);
		Client(Samurai::EventLoop& loop, ClientEventHandler* eh, std::string baseUrl,
		       Family family, const Options& options);
		~Client() override;

		Client(const Client&) = delete;
		Client& operator=(const Client&) = delete;

		void requestServerInfo();
		void requestWhoami();
		void openSession(const std::vector<std::string>& tests = {});

		/**
		 * Ask the server to probe these ports.
		 *
		 * The listeners must already be armed: the server connects back while
		 * this request is outstanding, so a client that asks first races the
		 * probe against its own bind.
		 */
		void requestInbound(const Session& session,
		                    const std::vector<uint16_t>& tcpPorts,
		                    const std::vector<uint16_t>& udpPorts);

		/** Abandon the request. No further event is delivered. */
		void abort();

		bool isBusy() const;

		Family getFamily() const { return family; }
		const std::string& getBaseUrl() const { return base_url; }

		/**
		 * The local port the last control connection used.
		 *
		 * Sent to the server as control_port, which compares it against the
		 * port it observed to detect source-port rewriting. Zero until a
		 * request has connected.
		 */
		uint16_t getControlPort() const { return control_port; }

		/** The local address the last control connection used. */
		const std::string& getControlAddress() const { return control_address; }

	private:
		enum class Pending { None, ServerInfo, Whoami, Session, Inbound };

		void EventHttpResponse(Samurai::IO::Net::HTTP::Client*,
		                       const Samurai::IO::Net::HTTP::Response&) override;
		void EventHttpError(Samurai::IO::Net::HTTP::Client*,
		                    Samurai::IO::Net::HTTP::Status, const char* msg) override;

		void internal_get(Pending what, const std::string& path);
		void internal_post(Pending what, const std::string& path,
		                   const std::string& body,
		                   std::chrono::milliseconds timeout);
		void internal_prepare(std::chrono::milliseconds timeout);
		void internal_fail(const ErrorInfo& info);

		Samurai::EventLoop& loop;
		ClientEventHandler* eventHandler;
		std::string base_url;
		Family family;
		Options options;

		std::unique_ptr<Samurai::IO::Net::HTTP::Client> http;
		Pending pending = Pending::None;

		uint16_t control_port = 0;
		std::string control_address;
};

}

#endif // HAVE_DROP_CLIENT_H
