/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/check.h>
#include <drop/types.h>
#include <drop/upnp.h>

#include <string>
#include <vector>

/* The small surfaces: enumerations, their spellings, and the URL derivation. */

namespace {

using namespace Drop;

} // namespace

EXO_TEST(types_routability_matches_what_a_probe_could_reach, {
	/* Tunnelled IPv6 is routable even though it is unpleasant; a shared or
	   private address is not, whatever the user does to their router. */
	return isRoutable(Classification::Global)
	    && isRoutable(Classification::Teredo)
	    && isRoutable(Classification::SixToFour)
	    && !isRoutable(Classification::CGNAT)
	    && !isRoutable(Classification::Private)
	    && !isRoutable(Classification::UniqueLocal)
	    && !isRoutable(Classification::Loopback)
	    && !isRoutable(Classification::LinkLocal)
	    && !isRoutable(Classification::Unknown);
});

EXO_TEST(types_classification_round_trips_through_its_spelling, {
	const Classification all[] = {
		Classification::Global, Classification::CGNAT, Classification::Private,
		Classification::UniqueLocal, Classification::Loopback,
		Classification::Teredo, Classification::SixToFour,
		Classification::LinkLocal,
	};

	for (Classification c : all)
	{
		if (classificationFromString(toString(c)) != c)
			return false;
	}
	return true;
});

EXO_TEST(types_verdict_round_trips_through_its_spelling, {
	const Verdict all[] = {
		Verdict::Open, Verdict::Occupied, Verdict::Refused, Verdict::Filtered,
		Verdict::NoResponse, Verdict::Error,
	};

	for (Verdict v : all)
	{
		if (verdictFromString(toString(v)) != v)
			return false;
	}
	return true;
});

EXO_TEST(types_every_enumerator_has_a_name, {
	const Verdict verdicts[] = {
		Verdict::Unknown, Verdict::Open, Verdict::Occupied, Verdict::Refused,
		Verdict::Filtered, Verdict::NoResponse, Verdict::Error,
	};
	for (Verdict v : verdicts)
	{
		if (!toString(v) || !*toString(v)) return false;
	}

	const Behaviour behaviours[] = {
		Behaviour::Unknown, Behaviour::None, Behaviour::Blocked,
		Behaviour::EndpointIndependent, Behaviour::AddressDependent,
		Behaviour::AddressAndPortDependent,
	};
	for (Behaviour b : behaviours)
	{
		if (!toString(b) || !*toString(b)) return false;
	}

	const Mode modes[] = { Mode::Active, Mode::Passive, Mode::Unknown };
	for (Mode m : modes)
	{
		if (!toString(m) || !*toString(m)) return false;
	}

	const Error errors[] = {
		Error::Ok, Error::InvalidUrl, Error::Transport, Error::Malformed,
		Error::NotADropServer, Error::Server, Error::RateLimited,
		Error::Local, Error::Unsupported,
	};
	for (Error e : errors)
	{
		if (!toString(e) || !*toString(e)) return false;
	}

	return std::string(toString(Family::IPv4)) == "ipv4"
	    && std::string(toString(Family::IPv6)) == "ipv6";
});

EXO_TEST(types_error_message_is_readable_in_every_combination, {
	ErrorInfo bare;
	bare.error = Error::Transport;

	ErrorInfo coded;
	coded.error = Error::Server;
	coded.code = "session_already_ran";

	ErrorInfo detailed;
	detailed.error = Error::Server;
	detailed.detail = "something";

	ErrorInfo both;
	both.error = Error::RateLimited;
	both.code = "rate_limited";
	both.detail = "try again in 196s";

	return bare.ok() == false
	    && !bare.message().empty()
	    && coded.message().find("session_already_ran") != std::string::npos
	    && detailed.message().find("something") != std::string::npos
	    && both.message().find("rate_limited") != std::string::npos
	    && both.message().find("196s") != std::string::npos
	    && ErrorInfo().ok();
});

EXO_TEST(types_finds_a_port_result_and_reports_absence, {
	InboundResult result;

	PortResult a;
	a.port = 1511;
	a.verdict = Verdict::Open;
	result.tcp.push_back(a);

	PortResult b;
	b.port = 1512;
	b.verdict = Verdict::NoResponse;
	result.udp.push_back(b);

	return result.findTcp(1511) != nullptr
	    && result.findTcp(1511)->verdict == Verdict::Open
	    && result.findUdp(1512) != nullptr
	    /* A port that was not tested is absent, not a fabricated verdict. */
	    && result.findTcp(1512) == nullptr
	    && result.findUdp(1511) == nullptr
	    && result.findTcp(0) == nullptr;
});

EXO_TEST(types_server_capabilities_are_per_family, {
	ServerInfo info;
	info.testsIPv4 = { "tcp", "udp", "egress" };
	info.testsIPv6 = { "tcp", "udp", "egress", "nat" };

	return info.supports(Family::IPv4, "tcp")
	    && !info.supports(Family::IPv4, "nat")
	    && info.supports(Family::IPv6, "nat")
	    && !info.supports(Family::IPv4, "")
	    && !info.supports(Family::IPv6, "invented");
});

EXO_TEST(check_derives_the_family_specific_url, {
	/*
	 * The family-specific names are what make the family under test
	 * unambiguous; relying on the dual-stack name would leave it to whichever
	 * connection Happy Eyeballs won.
	 */
	return familyUrl("https://drop.example.org", Family::IPv4)
	         == "https://ipv4.drop.example.org"
	    && familyUrl("https://drop.example.org", Family::IPv6)
	         == "https://ipv6.drop.example.org"
	    /* A trailing slash is not part of the host. */
	    && familyUrl("https://drop.example.org/", Family::IPv4)
	         == "https://ipv4.drop.example.org"
	    && familyUrl("https://drop.example.org///", Family::IPv6)
	         == "https://ipv6.drop.example.org"
	    /* http is derived the same way, though the client will refuse it. */
	    && familyUrl("http://drop.example.org", Family::IPv4)
	         == "http://ipv4.drop.example.org"
	    /* A bare host, for a caller that omitted the scheme. */
	    && familyUrl("drop.example.org", Family::IPv4)
	         == "ipv4.drop.example.org";
});

EXO_TEST(check_url_keeps_a_port_and_a_path, {
	return familyUrl("https://drop.example.org:8443", Family::IPv4)
	         == "https://ipv4.drop.example.org:8443";
});

EXO_TEST(upnp_applies_to_ipv4_only, {
	/*
	 * IGD forwards IPv4. An IPv6 host that cannot be reached has a firewall
	 * rather than a NAT in the way, and the honest answer there is to say so
	 * rather than to search for a gateway that will not help.
	 */
	return Upnp::isApplicable(Family::IPv4)
	    && !Upnp::isApplicable(Family::IPv6);
});

EXO_TEST(check_options_default_to_something_sensible, {
	const CheckOptions options;

	return options.families.size() == 2
	    && options.tcpPort == 0        /* ephemeral unless the caller names one */
	    && options.udpPort == 0
	    && !options.useUpnp            /* opening a port is not a default */
	    && !options.keepMapping
	    && !options.allowUntrustedCertificate
	    && options.testEgress
	    /* The server bounds /inbound at 15s, so the client must wait longer or
	       it gives up on results that were about to arrive. */
	    && options.inboundTimeout > std::chrono::milliseconds(15000);
});

EXO_TEST(upnp_result_starts_empty, {
	const UpnpResult result;
	return !result.gatewayFound
	    && !result.mappingAdded
	    && !result.retained
	    && result.tcpExternalPort == 0
	    && result.udpExternalPort == 0;
});
