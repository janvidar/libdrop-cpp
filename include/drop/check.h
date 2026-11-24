/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_CHECK_H
#define HAVE_DROP_CHECK_H

#include <drop/types.h>
#include <drop/upnp.h>

#include <samurai/eventloop.h>
#include <samurai/io/net/inetaddress.h>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace Drop {

/** What one run should do. */
struct CheckOptions
{
	/** Which families to test. Each is a separate run against its own name. */
	std::vector<Family> families{ Family::IPv4, Family::IPv6 };

	/**
	 * The ports to test. Zero asks the operating system for an ephemeral one,
	 * which is right for a diagnostic and wrong for a DC client: that should
	 * name the port it actually advertises, since a check of a different port
	 * says nothing about the one in its INF.
	 */
	uint16_t tcpPort = 0;
	uint16_t udpPort = 0;

	/**
	 * The address to test, which is also the address bound for everything.
	 *
	 * Leave unset on a host with one address per family. Set it where there is
	 * more than one, or the kernel decides which address the answer is about.
	 */
	std::optional<Samurai::IO::Net::InetAddress> localAddress;

	/**
	 * When the check says unreachable, ask the gateway for a mapping and run
	 * the inbound test again.
	 *
	 * This is the only way to find out whether UPnP actually helped. A router
	 * grants a mapping and reports success without knowing whether anything
	 * upstream will honour it.
	 */
	bool useUpnp = false;

	/**
	 * Keep a mapping that worked.
	 *
	 * A mapping that did not help is always removed, whatever this says:
	 * leaving a forward open to a port that could not be reached through it
	 * has no upside.
	 */
	bool keepMapping = false;

	bool testEgress = true;

	/** Not yet implemented; see the note in the Report. */
	bool discoverNat = true;

	bool allowUntrustedCertificate = false;

	std::string userAgent{ "libdrop-cpp/0.1" };
	std::chrono::milliseconds timeout{ 20000 };
	std::chrono::milliseconds inboundTimeout{ 30000 };

	Upnp::Options upnp;
};

/** Everything one address family's run established. */
struct FamilyReport
{
	Family family = Family::IPv4;
	std::string baseUrl;

	/** Set when the run could not be completed; the rest is then unfilled. */
	ErrorInfo error;

	ServerInfo server;
	Whoami whoami;
	InboundResult inbound;
	Decision decision;

	/** Observations about the run that belong to no single port. */
	std::vector<std::string> notes;

	std::vector<EgressResult> egress;

	bool upnpAttempted = false;
	UpnpResult upnp;
	/**
	 * The verdicts from before the mapping, when one was tried.
	 *
	 * Comparing these with 'inbound' is the answer the check-map-recheck loop
	 * exists to produce, and the only evidence that UPnP did anything: a
	 * router reports success either way.
	 */
	InboundResult inboundBeforeUpnp;
	Decision decisionBeforeUpnp;

	/**
	 * NAT behaviour discovery.
	 *
	 * natTested is false in this release: the RFC 5780 client is not written
	 * yet. The fields are here so that a caller written against them does not
	 * have to change when it lands.
	 */
	bool natTested = false;
	NatResult nat;
};

/** The whole run. */
struct Report
{
	std::string server;
	std::vector<FamilyReport> families;
	/** One sentence covering every family that was tested. */
	std::string advice;
};

/**
 * Run the whole flow and return what it found.
 *
 * Synchronous: it drives the loop it is given, so it MUST NOT be called from
 * inside an event handler nor while that loop is being run elsewhere. A client
 * that runs its loop itself should use Drop::Client and the responders
 * directly; src/check.cpp is the worked example of doing that.
 *
 * @param loop the loop every socket, timer and request of the run is made on.
 * @param baseUrl the dual-stack base, e.g. "https://drop.example.org". The
 *        family-specific names are derived by prefixing "ipv4." and "ipv6.",
 *        which is what makes the family under test unambiguous.
 */
Report check(Samurai::EventLoop& loop, const std::string& baseUrl,
             const CheckOptions& options = CheckOptions());

/** Run one family, for a caller that wants them separately. */
FamilyReport checkFamily(Samurai::EventLoop& loop, const std::string& baseUrl, Family family,
                         const CheckOptions& options = CheckOptions());

/** Turn "https://drop.example.org" into "https://ipv4.drop.example.org". */
std::string familyUrl(const std::string& baseUrl, Family family);

}

#endif // HAVE_DROP_CHECK_H
