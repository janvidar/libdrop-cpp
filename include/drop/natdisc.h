/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_NATDISC_H
#define HAVE_DROP_NATDISC_H

#include <drop/stun.h>
#include <drop/types.h>

#include <chrono>
#include <string>

namespace Drop {

/**
 * Client-side NAT behaviour discovery, RFC 5780.
 *
 * Answers "would hole punching work". That is a different question from "can
 * strangers reach my UDP port", and the two must never be substituted: every
 * request here is client-initiated and so traverses a mapping the client just
 * created. Only the DROP inbound UDP probe, which arrives from an endpoint the
 * client never contacted, answers the second question.
 *
 * Synchronous: it drives the socket monitor, so it MUST NOT be called from
 * inside an event handler.
 *
 * WHAT THIS NEEDS FROM THE SERVER: an OTHER-ADDRESS in the first response, and
 * a working CHANGE-REQUEST. Measured against five public STUN servers in
 * August 2026, three offered neither and the two that advertised
 * OTHER-ADDRESS ignored CHANGE-REQUEST - so the mapping half of RFC 5780 is
 * widely available and the filtering half effectively is not. Against a server
 * that cannot do it, filtering is reported Unknown and never as a restrictive
 * NAT: the two are indistinguishable from here, and guessing the restrictive
 * one sends users chasing a firewall problem they do not have.
 */
class NatDiscovery
{
	public:
		struct Options
		{
			/** The server's primary STUN endpoint. */
			Stun::Endpoint primary;

			/**
			 * The source address to bind, and therefore the address the answer
			 * is about.
			 *
			 * Should always be set. A host with several addresses of one
			 * family has no source address until one is named: the kernel
			 * picks per destination, preferring the address that shares the
			 * longest prefix with the target (RFC 6724). The mapping tests
			 * deliberately aim at two addresses of one server, so on such a
			 * host an unbound socket sends Test I and Test II from *different*
			 * addresses, the mapped addresses differ for that reason alone,
			 * and the result is address-dependent mapping reported for a
			 * machine with no NAT near it.
			 *
			 * Pass the address the control connection came from, which is what
			 * the rest of the check is about.
			 */
			std::string localAddress;

			/** Short-term credentials, when the caller has a session. */
			std::string username;
			std::string password;

			/** Per request, not for the whole run. */
			std::chrono::milliseconds timeout{ 3000 };
		};

		static NatResult discover(const Options& options);
};

}

#endif // HAVE_DROP_NATDISC_H
