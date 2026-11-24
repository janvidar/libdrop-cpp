/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/check.h>

#include <drop/client.h>
#include <drop/natdisc.h>
#include <drop/responder.h>
#include "pump.h"

#include <samurai/io/net/socket.h>
#include <samurai/io/net/socketaddress.h>
#include <samurai/io/net/socketevent.h>

#include <string.h>

/*
 * The whole flow, in the order the specification requires it:
 *
 *   capabilities -> reflexive address -> arm the listeners -> open a session
 *   -> ask for the probes -> apply the decision table
 *
 * Two orderings here are load-bearing rather than incidental. The listeners
 * are armed before the session is opened, because the server connects back
 * while the /inbound request is outstanding and a client that asks first races
 * the probe against its own bind. And the inbound test runs before anything
 * else touches the server's STUN endpoints, because once a client has sent to
 * them a NAT doing address-dependent filtering will let a datagram through
 * that it would have dropped from a stranger.
 */

namespace Drop {

namespace {

/** Collects the one event each control-plane request produces. */
class Collector final : public ClientEventHandler
{
	public:
		bool done = false;
		bool ok = false;
		ErrorInfo error;

		ServerInfo server;
		Whoami whoami;
		Session session;
		InboundResult inbound;

		void reset() { done = false; ok = false; error = ErrorInfo(); }

	protected:
		void EventDropServerInfo(Client*, const ServerInfo& value) override
		{ server = value; ok = true; done = true; }

		void EventDropWhoami(Client*, const Whoami& value) override
		{ whoami = value; ok = true; done = true; }

		void EventDropSession(Client*, const Session& value) override
		{ session = value; ok = true; done = true; }

		void EventDropInbound(Client*, const InboundResult& value) override
		{ inbound = value; ok = true; done = true; }

		void EventDropError(Client*, const ErrorInfo& info) override
		{ error = info; ok = false; done = true; }
};

/** Run one request to completion. */
bool await(Samurai::EventLoop& loop, Collector& events, std::chrono::milliseconds timeout)
{
	pump(loop, [&] { return events.done; }, timeout);
	if (!events.done)
	{
		events.error.error = Error::Transport;
		events.error.detail = "the server did not answer in time";
	}
	return events.ok;
}

/** The egress test: positive evidence on every port, never a bare connect. */
class EgressProbe final : public Samurai::IO::Net::SocketEventHandler
{
	public:
		bool finished = false;
		bool reached = false;
		std::string detail;

		void run(Samurai::EventLoop& loop, const std::string& host, uint16_t port,
		         const std::optional<Samurai::IO::Net::InetAddress>& localAddress,
		         std::chrono::milliseconds timeout)
		{
			socket = Samurai::IO::Net::Socket::create(loop, this, host, port);
			if (!socket)
			{
				finished = true;
				detail = "no socket";
				return;
			}
			if (localAddress)
				socket->setLocalAddress(*localAddress);
			socket->setConnectTimeout(timeout);
			socket->connect();

			pump(loop, [&] { return finished; }, timeout);
			if (!finished)
				detail = "timed out";

			socket->setEventHandler(nullptr);
			socket->disableMonitor();
			socket.reset();
		}

	protected:
		void EventDataAvailable(const Samurai::IO::Net::Socket* which) override
		{
			char buf[64];
			size_t got = 0;
			std::error_code ec;
			Samurai::IO::Net::Socket* s =
				const_cast<Samurai::IO::Net::Socket*>(which);
			if (s->read(buf, sizeof(buf) - 1, got, ec) != Samurai::IO::ReadResult::Ok)
			{
				finished = true;
				return;
			}
			buf[got] = 0;

			/*
			 * A bare connect proves nothing: the usual cause of blocked egress
			 * is a transparent proxy or captive portal that accepts the
			 * connection itself. Only the banner distinguishes the two.
			 */
			reached = (strncmp(buf, "DROP/1 EGRESS ", 14) == 0);
			if (!reached)
				detail = "something answered, but not this service";
			finished = true;
		}

		void EventDisconnected(const Samurai::IO::Net::Socket*) override
		{
			if (!reached && detail.empty())
				detail = "connected but no banner";
			finished = true;
		}

		void EventTimeout(const Samurai::IO::Net::Socket*) override
		{
			detail = "connection timed out";
			finished = true;
		}

		void EventError(const Samurai::IO::Net::Socket*,
		                Samurai::IO::Net::SocketError, const char* msg) override
		{
			detail = msg ? msg : "connection failed";
			finished = true;
		}

	private:
		std::shared_ptr<Samurai::IO::Net::Socket> socket;
};

std::vector<EgressResult> testEgress(Samurai::EventLoop& loop, const ServerInfo& server,
                                     Family family, const CheckOptions& options)
{
	std::vector<EgressResult> out;

	const std::string host =
		family == Family::IPv6 ? server.egressIPv6 : server.egressIPv4;
	if (host.empty())
		return out;

	for (uint16_t port : server.egressBannerPorts)
	{
		EgressProbe probe;
		probe.run(loop, host, port, options.localAddress, std::chrono::seconds(5));

		EgressResult result;
		result.port = port;
		result.reached = probe.reached;
		result.detail = probe.detail;
		out.push_back(std::move(result));
	}

	return out;
}

std::string bindAddressFor(const CheckOptions& options)
{
	return options.localAddress ? options.localAddress->toString() : std::string();
}

} // namespace

std::string familyUrl(const std::string& baseUrl, Family family)
{
	std::string base = baseUrl;
	while (!base.empty() && base.back() == '/')
		base.pop_back();

	const std::string prefix = (family == Family::IPv6) ? "ipv6." : "ipv4.";

	for (const char* scheme : { "https://", "http://" })
	{
		const size_t n = strlen(scheme);
		if (base.compare(0, n, scheme) == 0)
			return std::string(scheme) + prefix + base.substr(n);
	}
	return prefix + base;
}

FamilyReport checkFamily(Samurai::EventLoop& loop, const std::string& baseUrl,
                         Family family, const CheckOptions& options)
{
	FamilyReport report;
	report.family = family;
	report.baseUrl = familyUrl(baseUrl, family);

	Client::Options clientOptions;
	clientOptions.timeout = options.timeout;
	clientOptions.inboundTimeout = options.inboundTimeout;
	clientOptions.userAgent = options.userAgent;
	clientOptions.localAddress = options.localAddress;
	clientOptions.allowUntrustedCertificate = options.allowUntrustedCertificate;

	Collector events;
	Client client(loop, &events, report.baseUrl, family, clientOptions);

	/* Capabilities, which also confirms this is a DROP server rather than
	   something that answers 200 to everything. */
	events.reset();
	client.requestServerInfo();
	if (!await(loop, events, options.timeout))
	{
		report.error = events.error;
		return report;
	}
	report.server = events.server;

	/* The reflexive address. Half of what the caller came for, and free. */
	events.reset();
	client.requestWhoami();
	if (!await(loop, events, options.timeout))
	{
		report.error = events.error;
		return report;
	}
	report.whoami = events.whoami;

	/*
	 * Source-port rewriting, detected locally.
	 *
	 * These two are the ends of one connection: the port this client bound and
	 * the port the server saw. A difference is a NAT rewriting source ports,
	 * which tells the user a NAT is in the path before any probe verdict comes
	 * back. Doing it here rather than by sending control_port is what makes it
	 * correct - see the note in Client::requestInbound.
	 */
	if (const uint16_t localPort = client.getControlPort())
	{
		if (report.whoami.port && localPort != report.whoami.port)
		{
			report.notes.push_back(
				"This connection left your machine on port "
				+ std::to_string(localPort) + " but reached the server as port "
				+ std::to_string(report.whoami.port)
				+ ", so a NAT is rewriting source ports.");
		}
	}

	/*
	 * Arm the listeners before opening the session. The server connects back
	 * while /inbound is outstanding, so binding afterwards races the probe.
	 */
	const std::string bindAddress = bindAddressFor(options);

	TcpResponder tcp(loop);
	if (!tcp.listen(family, bindAddress, options.tcpPort))
	{
		report.error.error = Error::Local;
		report.error.detail = "could not listen for the TCP challenge";
		return report;
	}

	UdpResponder udp(loop);
	const bool wantUdp = report.server.supports(family, "udp");
	if (wantUdp && !udp.listen(family, bindAddress, options.udpPort))
	{
		report.error.error = Error::Local;
		report.error.detail = "could not listen for the UDP probe";
		return report;
	}

	events.reset();
	client.openSession();
	if (!await(loop, events, options.timeout))
	{
		report.error = events.error;
		return report;
	}
	const Session session = events.session;

	/* The responder must hold the credentials before the probe arrives, and
	   must answer nothing else. */
	if (wantUdp)
		udp.setCredentials(session.username, session.password);

	std::vector<uint16_t> tcpPorts{ tcp.getPort() };
	std::vector<uint16_t> udpPorts;
	if (wantUdp)
		udpPorts.push_back(udp.getPort());

	events.reset();
	client.requestInbound(session, tcpPorts, udpPorts);
	if (!await(loop, events, options.inboundTimeout))
	{
		report.error = events.error;
		return report;
	}
	report.inbound = events.inbound;

	const PortResult* tcpResult = report.inbound.findTcp(tcp.getPort());
	const PortResult* udpResult = wantUdp ? report.inbound.findUdp(udp.getPort())
	                                      : nullptr;
	report.decision = decide(family, report.whoami.classification,
	                         tcpResult, udpResult, tcp.getPort());

	/*
	 * UPnP, and then the whole inbound test again. Asking the gateway is the
	 * easy half; finding out whether it made any difference is the half that
	 * needs a second measurement from outside.
	 */
	if (options.useUpnp && report.decision.mode != Mode::Active &&
	    Upnp::isApplicable(family))
	{
		report.upnpAttempted = true;
		report.inboundBeforeUpnp = report.inbound;
		report.decisionBeforeUpnp = report.decision;

		report.upnp = Upnp::addMapping(loop, tcp.getPort(),
		                               wantUdp ? udp.getPort() : 0,
		                               bindAddress, options.upnp);

		if (report.upnp.mappingAdded)
		{
			/* A second session: the first is spent, single use being what
			   stops the rate limit from being a formality. */
			events.reset();
			client.openSession();
			if (await(loop, events, options.timeout))
			{
				const Session second = events.session;
				if (wantUdp)
					udp.setCredentials(second.username, second.password);

				events.reset();
				client.requestInbound(second, tcpPorts, udpPorts);
				if (await(loop, events, options.inboundTimeout))
				{
					report.inbound = events.inbound;

					const PortResult* t = report.inbound.findTcp(tcp.getPort());
					const PortResult* u = wantUdp
						? report.inbound.findUdp(udp.getPort()) : nullptr;
					report.decision = decide(family, report.whoami.classification,
					                         t, u, tcp.getPort());
				}
			}

			const bool helped = report.decision.mode == Mode::Active;
			if (helped)
			{
				report.upnp.retained = options.keepMapping;
				if (report.upnp.retained)
				{
					report.upnp.summary = "The gateway granted a mapping and it "
					                      "worked: inbound connections now reach "
					                      "you, and the mapping has been left in "
					                      "place.";
				}
				else
				{
					/*
					 * The verdict above was measured with the mapping in place,
					 * and the mapping is about to be removed - so it describes a
					 * state that will not exist once this run ends. Saying
					 * "active" and stopping there would have the user act on a
					 * reachability they no longer have.
					 */
					report.upnp.summary =
						"The gateway granted a mapping and it worked: with it in "
						"place, inbound connections reached you. It has now been "
						"removed, so you are passive again. Re-run with the "
						"mapping kept, or forward the port on your router, to "
						"make this permanent.";
				}
			}
			else
			{
				/*
				 * The interesting failure, and the reason this loop exists: the
				 * router said yes and it changed nothing, which almost always
				 * means a second NAT upstream.
				 */
				report.upnp.summary = "The gateway granted a mapping, but you "
				                      "still cannot be reached through it. There "
				                      "is very likely another NAT above your "
				                      "router, which no port forward here can "
				                      "get past.";
				report.upnp.retained = false;
			}

			if (!report.upnp.retained)
			{
				/* A forward to a port that could not be reached through it has
				   no upside and is a hole somebody has to notice later. */
				Upnp::removeMapping(loop, report.upnp.tcpExternalPort,
				                    report.upnp.udpExternalPort,
				                    options.upnp);
			}
		}
	}

	/*
	 * Behaviour discovery last of the measurements, and after the inbound test
	 * rather than before it. Once this has sent to the server's STUN
	 * endpoints, a NAT doing address-dependent filtering will admit a datagram
	 * from them that it would have dropped from a stranger - and a stranger is
	 * precisely who sends ADC search results.
	 */
	if (options.discoverNat && report.server.supports(family, "nat"))
	{
		NatDiscovery::Options natOptions;
		if (const std::optional<Stun::Endpoint> primary =
		        Stun::parseEndpoint(session.stunPrimary, session.stunPrimaryPort))
			natOptions.primary = *primary;

		/*
		 * The address the control connection came from, so the NAT answer is
		 * about the same address as everything else in this report. Without a
		 * pinned source the kernel picks per destination, and the mapping
		 * tests deliberately aim at two addresses of one server.
		 */
		natOptions.localAddress = bindAddress.empty()
			? client.getControlAddress() : bindAddress;
		natOptions.username = session.username;
		natOptions.password = session.password;

		if (natOptions.primary.valid())
		{
			report.nat = NatDiscovery::discover(loop, natOptions);
			report.natTested = true;
			applyNat(report.decision, report.nat);
		}
	}

	if (options.testEgress)
		report.egress = testEgress(loop, report.server, family, options);

	/*
	 * Once the check is over the responder should stop answering: the
	 * credentials are spent, and a client that keeps answering is a service
	 * nobody asked it to run.
	 */
	udp.clearCredentials();

	return report;
}

Report check(Samurai::EventLoop& loop, const std::string& baseUrl, const CheckOptions& options)
{
	Report report;
	report.server = baseUrl;

	std::vector<Decision> decisions;
	for (Family family : options.families)
	{
		FamilyReport fr = checkFamily(loop, baseUrl, family, options);
		if (fr.error.ok())
			decisions.push_back(fr.decision);
		report.families.push_back(std::move(fr));
	}

	report.advice = combine(decisions);
	return report;
}

}
