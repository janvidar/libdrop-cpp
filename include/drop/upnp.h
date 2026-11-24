/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_UPNP_H
#define HAVE_DROP_UPNP_H

#include <drop/types.h>

#include <chrono>
#include <string>

namespace Samurai { class EventLoop; }

namespace Drop {

/** What a mapping attempt achieved. */
struct UpnpResult
{
	/** A gateway answered the search and its description was read. */
	bool gatewayFound = false;
	std::string gatewayName;

	/** The address the gateway believes it has on the outside, when it says. */
	std::string externalAddress;

	bool mappingAdded = false;

	/*
	 * One pair per protocol. They are separate mappings and the gateway may
	 * move either of them independently when a port is already taken, so a
	 * single pair here would report one mapping's external port against the
	 * other's internal one.
	 */
	uint16_t tcpExternalPort = 0;
	uint16_t tcpInternalPort = 0;
	uint16_t udpExternalPort = 0;
	uint16_t udpInternalPort = 0;

	/**
	 * Whether the mapping was left in place.
	 *
	 * A mapping that did not help is always removed: leaving a forward open to
	 * a port that could not be reached through it has no upside and is a hole
	 * somebody has to notice later.
	 */
	bool retained = false;

	/** One line for the user, whatever the outcome. */
	std::string summary;

	/** Set when something failed, in the gateway's own terms where it has any. */
	std::string error;
};

/**
 * Ask the local gateway for a port mapping.
 *
 * Synchronous: it drives the loop it is given until the gateway answers, so it
 * MUST NOT be called from inside an event handler. Discovery is a multicast
 * search with a timeout, so a run where no gateway exists takes as long as
 * that timeout and then reports it plainly.
 *
 * This does not decide whether the mapping worked. That is what re-running the
 * DROP check afterwards is for, and it is the entire reason the mapping is
 * worth asking for through a checker rather than on its own: a router can
 * grant a mapping and report success while a second, carrier-grade NAT
 * upstream still drops every inbound packet. UPnP cannot see that. A probe
 * from outside can.
 */
/** How a mapping attempt should behave. */
struct UpnpOptions
{
	std::chrono::milliseconds searchTimeout{ 3000 };
	std::chrono::milliseconds actionTimeout{ 8000 };

	/**
	 * How long a mapping should live.
	 *
	 * Finite on purpose: a mapping left behind by a crash goes away by itself.
	 * Many gateways refuse a lease and Samurai's PortMapper falls back to a
	 * permanent one, which is better than failing.
	 */
	std::chrono::seconds lease{ 3600 };

	std::string description{ "DROP connectivity check" };
};

class Upnp
{
	public:
		using Options = UpnpOptions;

		/**
		 * Add a mapping for both TCP and UDP on the given ports.
		 *
		 * @param internalAddress the address to forward to, or empty to let the
		 *        gateway be told whichever of this host's addresses faces it.
		 */
		static UpnpResult addMapping(Samurai::EventLoop& loop,
		                             uint16_t tcpPort, uint16_t udpPort,
		                             const std::string& internalAddress,
		                             const UpnpOptions& options = UpnpOptions());

		/** Remove a mapping this process added. */
		static bool removeMapping(Samurai::EventLoop& loop,
		                          uint16_t tcpPort, uint16_t udpPort,
		                          const UpnpOptions& options = UpnpOptions());

		/** Whether UPnP is worth attempting at all for this family. */
		static bool isApplicable(Family family);
};

}

#endif // HAVE_DROP_UPNP_H
