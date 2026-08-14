/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/types.h>

#include <string>
#include <vector>

/*
 * The decision table is the part of this library other clients are meant to
 * reuse rather than reinvent, so every row of it has a case. A user who moves
 * between two DC clients and gets two different explanations of one network
 * concludes that one of them is broken; the way to prevent that is for there
 * to be one table, and for it to be pinned down.
 *
 * Pure logic. Nothing here touches a socket.
 */

namespace {

using namespace Drop;

PortResult result(Verdict verdict, uint16_t port = 1511)
{
	PortResult r;
	r.port = port;
	r.verdict = verdict;
	return r;
}

bool mentions(const std::string& text, const char* needle)
{
	return text.find(needle) != std::string::npos;
}

bool anyRemedyMentions(const Decision& d, const char* needle)
{
	for (const std::string& remedy : d.remedies)
	{
		if (mentions(remedy, needle))
			return true;
	}
	return false;
}

} // namespace

EXO_TEST(decide_tcp_and_udp_open_is_active, {
	const PortResult tcp = result(Verdict::Open);
	const PortResult udp = result(Verdict::Open);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, &udp, 1511);

	return d.mode == Mode::Active
	    && d.advertisePort == 1511
	    && mentions(d.reason, "Active mode works");
});

EXO_TEST(decide_tcp_open_udp_silent_is_active_with_a_warning, {
	/* Transfers work; search results will not arrive. Still active. */
	const PortResult tcp = result(Verdict::Open);
	const PortResult udp = result(Verdict::NoResponse);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, &udp, 1511);

	return d.mode == Mode::Active
	    && d.advertisePort == 1511
	    && mentions(d.reason, "search results may not arrive");
});

EXO_TEST(decide_udp_open_but_tcp_filtered_is_passive, {
	/*
	 * ADC cannot express "passive for transfers, reachable for searches".
	 * Advertising anyway makes remote clients attempt CTM to a port that never
	 * answers, which is worse for everyone than being honestly passive.
	 */
	const PortResult tcp = result(Verdict::Filtered);
	const PortResult udp = result(Verdict::Open);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, &udp, 1511);

	return d.mode == Mode::Passive
	    && d.advertisePort == 0
	    && mentions(d.reason, "no way to advertise that combination");
});

EXO_TEST(decide_refused_says_it_is_fixable_locally, {
	const PortResult tcp = result(Verdict::Refused);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	return d.mode == Mode::Passive
	    && mentions(d.reason, "fixable locally")
	    && anyRemedyMentions(d, "listening");
});

EXO_TEST(decide_occupied_points_at_the_forward_target, {
	const PortResult tcp = result(Verdict::Occupied);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	return d.mode == Mode::Passive
	    && mentions(d.reason, "not this client")
	    && anyRemedyMentions(d, "destination address");
});

EXO_TEST(decide_filtered_is_the_port_forwarding_case, {
	const PortResult tcp = result(Verdict::Filtered);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	return d.mode == Mode::Passive
	    && mentions(d.reason, "silently dropped")
	    && anyRemedyMentions(d, "Forward the port")
	    /* Re-checking afterwards matters: a router reports success while a
	       second NAT upstream still blocks. */
	    && anyRemedyMentions(d, "Re-run");
});

EXO_TEST(decide_cgnat_does_not_send_the_user_to_the_router, {
	/* No router setting can fix a shared address, so suggesting one wastes an
	   evening. */
	const PortResult tcp = result(Verdict::Filtered);
	const Decision d = decide(Family::IPv4, Classification::CGNAT, &tcp, nullptr, 1511);

	if (d.mode != Mode::Passive) return false;
	if (!mentions(d.reason, "carrier-grade NAT")) return false;
	if (!anyRemedyMentions(d, "IPv6")) return false;

	for (const std::string& remedy : d.remedies)
	{
		if (mentions(remedy, "Forward the port"))
			return false;
	}
	return true;
});

EXO_TEST(decide_tunnelled_ipv6_is_named, {
	const PortResult tcp = result(Verdict::Filtered);

	const Decision teredo =
		decide(Family::IPv6, Classification::Teredo, &tcp, nullptr, 1511);
	const Decision sixtofour =
		decide(Family::IPv6, Classification::SixToFour, &tcp, nullptr, 1511);

	return mentions(teredo.reason, "teredo")
	    && mentions(sixtofour.reason, "6to4")
	    && anyRemedyMentions(teredo, "native IPv6");
});

EXO_TEST(decide_a_private_observed_address_is_unknown_not_passive, {
	/* A proxy or middlebox is rewriting traffic, so no verdict from here means
	   anything, and reporting one sends the user somewhere useless. */
	const Classification proxied[] = {
		Classification::Private, Classification::UniqueLocal,
		Classification::Loopback, Classification::LinkLocal,
	};

	for (Classification c : proxied)
	{
		/* Even with everything open, which is the point: the measurement is
		   not about this machine's public reachability at all. */
		const PortResult tcp = result(Verdict::Open);
		const PortResult udp = result(Verdict::Open);
		const Decision d = decide(Family::IPv4, c, &tcp, &udp, 1511);

		if (d.mode != Mode::Unknown) return false;
		if (d.advertisePort != 0) return false;
		if (!mentions(d.reason, "proxy or middlebox")) return false;
	}
	return true;
});

EXO_TEST(decide_a_server_side_error_is_not_a_verdict_about_this_network, {
	/* "The server could not perform the probe" must never be reported to a
	   user as "your firewall is blocking". */
	const PortResult tcp = result(Verdict::Error);
	const Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	return d.mode == Mode::Unknown
	    && mentions(d.reason, "problem at the server");
});

EXO_TEST(decide_only_active_advertises_a_port, {
	/* Advertising while passive makes remote clients waste time on
	   connections that cannot succeed. */
	struct Case { Classification c; Verdict tcp; Verdict udp; };
	const Case cases[] = {
		{ Classification::Global, Verdict::Filtered,   Verdict::Open },
		{ Classification::Global, Verdict::Refused,    Verdict::NoResponse },
		{ Classification::Global, Verdict::Occupied,   Verdict::NoResponse },
		{ Classification::CGNAT,  Verdict::Filtered,   Verdict::NoResponse },
		{ Classification::Private, Verdict::Open,      Verdict::Open },
		{ Classification::Global, Verdict::Error,      Verdict::NoResponse },
	};

	for (const Case& c : cases)
	{
		const PortResult tcp = result(c.tcp);
		const PortResult udp = result(c.udp);
		const Decision d = decide(Family::IPv4, c.c, &tcp, &udp, 1511);
		if (d.mode != Mode::Active && d.advertisePort != 0)
			return false;
	}
	return true;
});

EXO_TEST(decide_always_gives_a_reason, {
	const Verdict verdicts[] = {
		Verdict::Open, Verdict::Occupied, Verdict::Refused, Verdict::Filtered,
		Verdict::NoResponse, Verdict::Error, Verdict::Unknown,
	};
	const Classification classes[] = {
		Classification::Global, Classification::CGNAT, Classification::Private,
		Classification::Teredo, Classification::SixToFour,
		Classification::Unknown,
	};

	for (Verdict v : verdicts)
	{
		for (Classification c : classes)
		{
			const PortResult tcp = result(v);
			const Decision d = decide(Family::IPv4, c, &tcp, nullptr, 1511);
			if (d.reason.empty())
				return false;
			/* A passive verdict on an address that could in principle be
			   reached should suggest something to try. */
			if (d.mode == Mode::Passive && c == Classification::Global &&
			    d.remedies.empty())
				return false;
		}
	}
	return true;
});

EXO_TEST(decide_tolerates_missing_results, {
	/* A server that ran only what it could is answering honestly; the client
	   must not crash on the absence. */
	const Decision none = decide(Family::IPv4, Classification::Global,
	                             nullptr, nullptr, 1511);
	const PortResult udp = result(Verdict::Open);
	const Decision udpOnly = decide(Family::IPv4, Classification::Global,
	                                nullptr, &udp, 1511);

	return !none.reason.empty() && none.mode != Mode::Active
	    && !udpOnly.reason.empty();
});

/* --- applyNat ------------------------------------------------------------ */

EXO_TEST(apply_nat_reports_blocked_udp, {
	const PortResult tcp = result(Verdict::Filtered);
	Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	NatResult nat;
	nat.mapping = Behaviour::Blocked;
	applyNat(d, nat);

	return mentions(d.note, "Outbound UDP is blocked");
});

EXO_TEST(apply_nat_is_silent_when_it_could_not_classify, {
	/* A server that cannot classify must not be reported as a restrictive
	   NAT: that sends users chasing a firewall problem they do not have. */
	const PortResult tcp = result(Verdict::Filtered);
	Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);

	NatResult nat;
	nat.mapping = Behaviour::Unknown;
	nat.filtering = Behaviour::Unknown;
	applyNat(d, nat);

	return d.note.empty();
});

EXO_TEST(apply_nat_is_silent_on_an_unknown_verdict, {
	/*
	 * Saying "reachability cannot be measured" and then volunteering NAT
	 * advice reads as a contradiction and invites the user to act on it.
	 */
	const PortResult tcp = result(Verdict::Open);
	Decision d = decide(Family::IPv4, Classification::Private, &tcp, nullptr, 1511);
	const size_t before = d.remedies.size();

	NatResult nat;
	nat.mapping = Behaviour::EndpointIndependent;
	nat.filtering = Behaviour::EndpointIndependent;
	applyNat(d, nat);

	return d.mode == Mode::Unknown && d.note.empty()
	    && d.remedies.size() == before;
});

EXO_TEST(apply_nat_suggests_hole_punching_only_when_it_could_work, {
	const PortResult tcp = result(Verdict::Filtered);

	Decision good = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);
	NatResult friendly;
	friendly.mapping = Behaviour::EndpointIndependent;
	friendly.filtering = Behaviour::EndpointIndependent;
	applyNat(good, friendly);

	Decision bad = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);
	NatResult hostile;
	hostile.mapping = Behaviour::AddressAndPortDependent;
	hostile.filtering = Behaviour::AddressAndPortDependent;
	applyNat(bad, hostile);

	return mentions(good.note, "hole punching")
	    && anyRemedyMentions(good, "NAT traversal")
	    && mentions(bad.note, "will not work reliably")
	    && !anyRemedyMentions(bad, "NAT traversal");
});

EXO_TEST(apply_nat_never_changes_the_mode, {
	/*
	 * Behaviour discovery is all client-initiated, so a good result says
	 * nothing about whether strangers can reach the client.
	 */
	const Behaviour mappings[] = {
		Behaviour::None, Behaviour::EndpointIndependent,
		Behaviour::AddressDependent, Behaviour::AddressAndPortDependent,
		Behaviour::Blocked, Behaviour::Unknown,
	};

	for (Behaviour m : mappings)
	{
		const PortResult tcp = result(Verdict::Filtered);
		Decision d = decide(Family::IPv4, Classification::Global, &tcp, nullptr, 1511);
		const Mode before = d.mode;

		NatResult nat;
		nat.mapping = m;
		nat.filtering = Behaviour::EndpointIndependent;
		applyNat(d, nat);

		if (d.mode != before) return false;
	}
	return true;
});

EXO_TEST(nat_hole_punch_prognosis, {
	struct Case { Behaviour mapping; Behaviour filtering; bool likely; };
	const Case cases[] = {
		{ Behaviour::None,                    Behaviour::EndpointIndependent,     true },
		{ Behaviour::EndpointIndependent,     Behaviour::EndpointIndependent,     true },
		{ Behaviour::EndpointIndependent,     Behaviour::AddressDependent,        true },
		{ Behaviour::EndpointIndependent,     Behaviour::AddressAndPortDependent, false },
		{ Behaviour::AddressDependent,        Behaviour::EndpointIndependent,     false },
		{ Behaviour::AddressAndPortDependent, Behaviour::EndpointIndependent,     false },
		{ Behaviour::Blocked,                 Behaviour::Blocked,                 false },
	};

	for (const Case& c : cases)
	{
		NatResult nat;
		nat.mapping = c.mapping;
		nat.filtering = c.filtering;
		if (nat.holePunchLikely() != c.likely) return false;
		if (nat.summary().empty()) return false;
	}
	return true;
});

/* --- combine -------------------------------------------------------------- */

EXO_TEST(combine_passive_everywhere, {
	const std::vector<Decision> decisions = {
		Decision{ Family::IPv4, Mode::Passive, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
		Decision{ Family::IPv6, Mode::Passive, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
	};
	return mentions(combine(decisions), "Passive on every address family");
});

EXO_TEST(combine_active_on_v6_only_is_a_good_position, {
	/*
	 * Materially better than passive on both, and worth saying: an
	 * IPv6-active client can connect directly with any other IPv6 client,
	 * which is most of what CGNAT would otherwise cost it.
	 */
	const std::vector<Decision> decisions = {
		Decision{ Family::IPv4, Mode::Passive, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
		Decision{ Family::IPv6, Mode::Active,  0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
	};
	return mentions(combine(decisions), "good position");
});

EXO_TEST(combine_active_on_both, {
	const std::vector<Decision> decisions = {
		Decision{ Family::IPv4, Mode::Active, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
		Decision{ Family::IPv6, Mode::Active, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
	};
	return mentions(combine(decisions), "both address families");
});

EXO_TEST(combine_does_not_describe_a_family_that_was_not_tested, {
	/* A family that errored produces no decision at all, and claiming it is
	   passive asserts more than the run established. */
	const std::vector<Decision> onlyV4 = {
		Decision{ Family::IPv4, Mode::Active, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
	};
	const std::string text = combine(onlyV4);

	return !mentions(text, "passive on IPv6") && mentions(text, "not tested");
});

EXO_TEST(combine_reports_nothing_measurable_as_such, {
	const std::vector<Decision> unknowns = {
		Decision{ Family::IPv4, Mode::Unknown, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
		Decision{ Family::IPv6, Mode::Unknown, 0, "", {}, "", Verdict::Unknown, Verdict::Unknown },
	};
	return mentions(combine(unknowns), "could not be determined");
});

EXO_TEST(combine_with_nothing_at_all, {
	return mentions(combine({}), "No address family could be tested");
});
