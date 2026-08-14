/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

/*
 * dropcheck: run the DROP flow and print what a user needs to know.
 *
 * Also the worked example. A client author should be able to read this top to
 * bottom and see the whole protocol, so it favours being obvious over being
 * short.
 */

#include <drop/check.h>
#include <drop/types.h>

#include <samurai/io/net/inetaddress.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <string>
#include <vector>

namespace {

void usage(const char* argv0)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"\n"
		"  --server URL     base URL, e.g. https://drop.example.org (required)\n"
		"  --family WHICH   ipv4, ipv6 or both (default: both)\n"
		"  --tcp-port N     the TCP port to test (default: an ephemeral one)\n"
		"  --udp-port N     the UDP port to test (default: an ephemeral one)\n"
		"  --bind ADDR      the local address to test; also what gets bound\n"
		"  --upnp           if unreachable, add a UPnP mapping and test again\n"
		"  --keep-mapping   leave a UPnP mapping in place when it worked\n"
		"  --no-nat         skip NAT behaviour discovery\n"
		"  --no-egress      skip the outbound-reachability test\n"
		"  --insecure       accept an unverifiable server certificate\n"
		"  --help\n",
		argv0);
}

/** Wrap at 78 columns with a hanging indent, so long advice stays readable. */
void wrap(const std::string& text, int indent)
{
	const size_t width = 78;
	std::string line(static_cast<size_t>(indent), ' ');
	size_t col = static_cast<size_t>(indent);
	bool first = true;

	size_t i = 0;
	while (i < text.size())
	{
		while (i < text.size() && text[i] == ' ') i++;
		size_t end = text.find(' ', i);
		if (end == std::string::npos) end = text.size();
		const std::string word = text.substr(i, end - i);
		i = end;

		if (!word.empty())
		{
			if (!first && col + 1 + word.size() > width)
			{
				printf("%s\n", line.c_str());
				line.assign(static_cast<size_t>(indent), ' ');
				col = static_cast<size_t>(indent);
				first = true;
			}
			if (!first) { line += ' '; col++; }
			line += word;
			col += word.size();
			first = false;
		}
	}
	if (!first) printf("%s\n", line.c_str());
}

/** A bullet whose continuation lines hang under the text, not the marker. */
void wrapBullet(const std::string& text, int indent)
{
	printf("%*s- ", indent, "");
	/* The first line is already positioned, so only the rest is indented. */
	std::string body = text;
	const size_t width = 78 - (size_t) indent - 2;
	size_t start = 0;
	bool first = true;
	while (start < body.size())
	{
		size_t take = body.size() - start;
		if (take > width)
		{
			size_t brk = body.rfind(' ', start + width);
			take = (brk != std::string::npos && brk > start) ? brk - start : width;
		}
		if (!first) printf("%*s", indent + 2, "");
		printf("%.*s\n", (int) take, body.c_str() + start);
		start += take;
		while (start < body.size() && body[start] == ' ') start++;
		first = false;
	}
}

void printFamily(const Drop::FamilyReport& report)
{
	printf("== %s ==\n", report.family == Drop::Family::IPv6 ? "IPV6" : "IPV4");

	if (!report.error.ok())
	{
		printf("  could not test: %s\n\n", report.error.message().c_str());
		return;
	}

	printf("  Public address:  %s (%s)\n", report.whoami.ip.c_str(),
	       toString(report.whoami.classification));
	if (!report.whoami.advice.empty() &&
	    report.whoami.classification != Drop::Classification::Global)
		wrap(report.whoami.advice, 19);

	for (const Drop::PortResult& r : report.inbound.tcp)
		printf("  Inbound TCP:     port %u: %s%s%s\n", r.port, toString(r.verdict),
		       r.detail.empty() ? "" : " - ", r.detail.c_str());
	for (const Drop::PortResult& r : report.inbound.udp)
		printf("  Inbound UDP:     port %u: %s%s%s\n", r.port, toString(r.verdict),
		       r.detail.empty() ? "" : " - ", r.detail.c_str());

	for (const std::string& note : report.notes)
		wrap("Note: " + note, 19);
	for (const std::string& note : report.inbound.notes)
		wrap("Note: " + note, 19);

	if (report.natTested)
	{
		printf("  NAT mapping:     %s\n", toString(report.nat.mapping));
		printf("  NAT filtering:   %s\n", toString(report.nat.filtering));
		if (report.nat.mapping != Drop::Behaviour::None &&
		    report.nat.mapping != Drop::Behaviour::Blocked)
			printf("  Port preserved:  %s\n", report.nat.portPreserving ? "yes" : "no");
		for (const std::string& note : report.nat.notes)
			wrap("Note: " + note, 19);
	}

	if (!report.egress.empty())
	{
		std::string blocked;
		for (const Drop::EgressResult& e : report.egress)
		{
			if (e.reached) continue;
			if (!blocked.empty()) blocked += ", ";
			blocked += std::to_string(e.port);
		}
		if (blocked.empty())
			printf("  Outbound:        all tested ports reachable\n");
		else
			printf("  Outbound:        blocked on %s\n", blocked.c_str());
	}

	if (report.upnpAttempted)
	{
		printf("\n  UPnP:\n");
		if (report.upnp.mappingAdded)
		{
			if (report.upnp.tcpExternalPort)
				printf("    mapped TCP %u -> %u\n", report.upnp.tcpExternalPort,
				       report.upnp.tcpInternalPort);
			if (report.upnp.udpExternalPort)
				printf("    mapped UDP %u -> %u\n", report.upnp.udpExternalPort,
				       report.upnp.udpInternalPort);

			/* The before and after, which is the only evidence the mapping did
			   anything: a router reports success either way. */
			for (const Drop::PortResult& before : report.inboundBeforeUpnp.tcp)
			{
				const Drop::PortResult* after = report.inbound.findTcp(before.port);
				if (after && after->verdict != before.verdict)
					printf("    TCP %u: %s -> %s\n", before.port,
					       toString(before.verdict), toString(after->verdict));
			}
			for (const Drop::PortResult& before : report.inboundBeforeUpnp.udp)
			{
				const Drop::PortResult* after = report.inbound.findUdp(before.port);
				if (after && after->verdict != before.verdict)
					printf("    UDP %u: %s -> %s\n", before.port,
					       toString(before.verdict), toString(after->verdict));
			}
			printf("    mapping %s\n",
			       report.upnp.retained ? "left in place" : "removed again");
		}
		wrap(report.upnp.summary, 4);
	}

	std::string mode = toString(report.decision.mode);
	for (char& c : mode) c = (char) toupper((unsigned char) c);

	/* A verdict measured through a mapping that has since been removed does
	   not describe the state the user is left in. */
	const bool transient = report.upnpAttempted
	                    && report.upnp.mappingAdded
	                    && !report.upnp.retained
	                    && report.decision.mode == Drop::Mode::Active;

	printf("\n  VERDICT:         %s%s\n", mode.c_str(),
	       transient ? "  (only while the UPnP mapping was in place)" : "");
	wrap(report.decision.reason, 2);
	if (!report.decision.note.empty())
		wrap(report.decision.note, 2);

	if (!report.decision.remedies.empty())
	{
		printf("\n  What to try:\n");
		for (const std::string& remedy : report.decision.remedies)
			wrapBullet(remedy, 4);
	}
	printf("\n");
}

} // namespace

int main(int argc, char** argv)
{
	Drop::CheckOptions options;
	std::string server;
	std::string family = "both";
	std::string bind;

	for (int i = 1; i < argc; i++)
	{
		const std::string arg = argv[i];
		const bool hasNext = (i + 1) < argc;

		if (arg == "--help" || arg == "-h") { usage(argv[0]); return 0; }
		else if (arg == "--server" && hasNext)     server = argv[++i];
		else if (arg == "--family" && hasNext)     family = argv[++i];
		else if (arg == "--bind" && hasNext)       bind = argv[++i];
		else if (arg == "--tcp-port" && hasNext)   options.tcpPort = (uint16_t) atoi(argv[++i]);
		else if (arg == "--udp-port" && hasNext)   options.udpPort = (uint16_t) atoi(argv[++i]);
		else if (arg == "--upnp")                  options.useUpnp = true;
		else if (arg == "--keep-mapping")          options.keepMapping = true;
		else if (arg == "--no-nat")                options.discoverNat = false;
		else if (arg == "--no-egress")             options.testEgress = false;
		else if (arg == "--insecure")              options.allowUntrustedCertificate = true;
		else
		{
			fprintf(stderr, "dropcheck: unknown option %s\n", arg.c_str());
			usage(argv[0]);
			return 2;
		}
	}

	if (server.empty())
	{
		fprintf(stderr, "dropcheck: --server is required\n");
		usage(argv[0]);
		return 2;
	}

	if (!bind.empty())
		options.localAddress = Samurai::IO::Net::InetAddress(bind);

	if (family == "ipv4")      options.families = { Drop::Family::IPv4 };
	else if (family == "ipv6") options.families = { Drop::Family::IPv6 };
	else if (family == "both") options.families = { Drop::Family::IPv4, Drop::Family::IPv6 };
	else
	{
		fprintf(stderr, "dropcheck: --family must be ipv4, ipv6 or both\n");
		return 2;
	}

	const Drop::Report report = Drop::check(server, options);

	for (const Drop::FamilyReport& fr : report.families)
		printFamily(fr);

	printf("== SUMMARY ==\n");
	wrap(report.advice, 2);

	/* Non-zero when nothing could be established, so a script can tell an
	   inconclusive run from a conclusive "passive". */
	for (const Drop::FamilyReport& fr : report.families)
	{
		if (fr.error.ok())
			return 0;
	}
	return 1;
}
