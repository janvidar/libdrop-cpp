/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/types.h>

#include <string>

/*
 * The specification's decision table.
 *
 * Two things about ADC shape every outcome here. Active mode is signalled by
 * the TCP4/TCP6 feature tokens in the INF SU field, while U4/U6 carry the UDP
 * port for search results, and deployed hubs disagree about which of the two
 * they look at - uhub counts U4/U6 and does not recognise TCP4 at all - so a
 * client has to set them consistently. And there is no way in ADC to say
 * "passive for transfers but reachable for search results": advertising U4/U6
 * is read as a wholesale active-mode claim.
 */

namespace Drop {

namespace {

bool isOpen(const PortResult* result)
{
	return result && result->verdict == Verdict::Open;
}

} // namespace

Decision decide(Family family, Classification classification,
                const PortResult* tcp, const PortResult* udp, uint16_t tcpPort)
{
	Decision d;
	d.family = family;
	d.mode = Mode::Passive;
	if (tcp) d.tcp = tcp->verdict;
	if (udp) d.udp = udp->verdict;

	/*
	 * A private or loopback address observed by a public server means a proxy
	 * or middlebox is rewriting traffic. No verdict from here means anything,
	 * and reporting one sends the user somewhere useless.
	 */
	if (classification == Classification::Private ||
	    classification == Classification::UniqueLocal ||
	    classification == Classification::Loopback ||
	    classification == Classification::LinkLocal)
	{
		d.mode = Mode::Unknown;
		d.reason = "A private address reached the server, so a proxy or middlebox "
		           "is rewriting your traffic. Reachability cannot be measured "
		           "from here.";
		return d;
	}

	/* A probe the server could not perform says nothing about this network. */
	if (tcp && tcp->verdict == Verdict::Error)
	{
		d.mode = Mode::Unknown;
		d.reason = "The server could not carry out the test. This is a problem "
		           "at the server, not with your connection.";
		return d;
	}

	const bool tcpOpen = isOpen(tcp);
	const bool udpOpen = isOpen(udp);

	if (tcpOpen && udpOpen)
	{
		d.mode = Mode::Active;
		d.advertisePort = tcpPort;
		d.reason = "Inbound TCP and UDP both reach you. Active mode works.";
	}
	else if (tcpOpen)
	{
		/* Transfers will work; search results over UDP will not arrive. */
		d.mode = Mode::Active;
		d.advertisePort = tcpPort;
		d.reason = "Inbound TCP reaches you, but unsolicited UDP does not. "
		           "Transfers will work; search results may not arrive.";
		d.remedies.push_back("Forward the same port for UDP as well as TCP.");
	}
	else if (udpOpen)
	{
		/*
		 * ADC cannot express this. Advertising anyway makes remote clients
		 * attempt CTM to a port that never answers, which is worse for
		 * everyone than being honestly passive.
		 */
		d.reason = "UDP reaches you but inbound TCP does not. ADC has no way to "
		           "advertise that combination, so passive mode is the honest "
		           "choice.";
		d.remedies.push_back("Forward the TCP port as well; the UDP forward "
		                     "alone is not enough.");
	}
	else if (tcp && tcp->verdict == Verdict::Refused)
	{
		d.reason = "The connection was refused: packets reach your network and "
		           "nothing is listening. Nothing is being dropped, so this is "
		           "usually fixable locally.";
		d.remedies.push_back("Check the client is actually listening on that port.");
		d.remedies.push_back("Check any port forward points at this machine, "
		                     "not another one.");
	}
	else if (tcp && tcp->verdict == Verdict::Occupied)
	{
		d.reason = "Something answered on that port, but it was not this client. "
		           "A forward is probably pointing at the wrong host.";
		d.remedies.push_back("Check the port forward's destination address.");
		d.remedies.push_back("Try a different port.");
	}
	else if (classification == Classification::CGNAT)
	{
		/* The one case where no amount of router configuration helps. */
		d.reason = "Your ISP uses carrier-grade NAT: this address is shared with "
		           "other subscribers, so inbound connections cannot be forwarded "
		           "to you.";
		d.remedies.push_back("Enable IPv6 if your ISP offers it; that is the real fix.");
		d.remedies.push_back("Ask your ISP for a public IPv4 address, which some "
		                     "provide on request.");
	}
	else if (classification == Classification::Teredo ||
	         classification == Classification::SixToFour)
	{
		d.reason = std::string("Your IPv6 connectivity is tunnelled (")
		         + toString(classification)
		         + ") and inbound connections are not getting through.";
		d.remedies.push_back("Use native IPv6 if your ISP offers it.");
	}
	else
	{
		d.reason = "Inbound connections are being silently dropped: a firewall "
		           "or NAT is in the way.";
		d.remedies.push_back("Forward the port on your router, or enable "
		                     "UPnP-IGD / NAT-PMP / PCP.");
		d.remedies.push_back("Check the firewall on this machine allows inbound "
		                     "connections.");
		d.remedies.push_back("Re-run this check afterwards: a router can report "
		                     "success while a second NAT upstream still blocks "
		                     "inbound.");
	}

	return d;
}

void applyNat(Decision& decision, const NatResult& nat)
{
	/*
	 * When the observed address already said a proxy is in the path, every
	 * measurement is suspect. Volunteering NAT advice on top of "reachability
	 * cannot be measured" reads as a contradiction and invites the user to act
	 * on it.
	 */
	if (decision.mode == Mode::Unknown)
		return;

	if (nat.mapping == Behaviour::Blocked)
	{
		decision.note = "Outbound UDP is blocked entirely, so UDP search results "
		                "cannot work on this network regardless of port forwarding.";
		return;
	}

	/* A server that could not classify must not be reported as a bad NAT. */
	if (nat.mapping == Behaviour::Unknown)
		return;

	/* Hole punching is moot when inbound already works. */
	if (decision.mode == Mode::Active)
		return;

	if (nat.holePunchLikely())
	{
		decision.note = "Your NAT is well behaved, so hole punching (ADC's NATT "
		                "extension) has a good chance of working with other clients.";
		decision.remedies.push_back("Enable NAT traversal in your client if it "
		                            "supports it.");
	}
	else
	{
		decision.note = std::string("Your NAT uses ") + toString(nat.mapping)
		              + " mapping, so hole punching will not work reliably. A "
		                "forwarded port is the only dependable option.";
	}
}

std::string combine(const std::vector<Decision>& decisions)
{
	std::vector<Family> active;
	size_t measured = 0;

	for (const Decision& d : decisions)
	{
		if (d.mode == Mode::Active) active.push_back(d.family);
		if (d.mode != Mode::Unknown) measured++;
	}

	if (decisions.empty())
		return "No address family could be tested.";

	if (measured == 0)
	{
		/* "Passive" would assert more than the evidence supports. */
		return "Reachability could not be determined on any address family, so "
		       "no change to your active-mode setting is recommended.";
	}

	const bool both = decisions.size() > 1;

	if (active.empty())
	{
		return "Passive on every address family that could be tested. Other "
		       "clients will not be able to connect to you directly, and "
		       "transfers with other passive users will not work at all.";
	}

	if (active.size() == 1)
	{
		if (active[0] == Family::IPv6)
		{
			if (!both)
				return "Active on IPv6. IPv4 was not tested.";
			/*
			 * Materially better than passive on both, and worth saying so: an
			 * IPv6-active client can connect directly with any other IPv6
			 * client, which is most of what CGNAT would otherwise cost it.
			 */
			return "Active on IPv6, passive on IPv4. This is a good position: "
			       "you can connect directly with any other IPv6 client, which "
			       "is most of what carrier-grade NAT would otherwise cost you.";
		}
		if (!both)
			return "Active on IPv4. IPv6 was not tested.";
		return "Active on IPv4, passive on IPv6.";
	}

	return "Active on both address families.";
}

}
