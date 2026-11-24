/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/upnp.h>

#include "pump.h"

#include <samurai/io/net/upnp/gateway.h>
#include <samurai/io/net/upnp/portmapper.h>

#include <stdio.h>

#include <memory>

namespace UPnP = Samurai::IO::Net::UPnP;

namespace Drop {

namespace {

/**
 * Drives a discovery and then a sequence of mapping actions to completion.
 *
 * One object implements both handlers because the two are one operation from
 * the caller's point of view: there is no useful state where the gateway has
 * been found but nothing has been asked of it.
 */
class GatewaySession final
	: public UPnP::GatewayEventHandler
	, public UPnP::PortMapperEventHandler
{
	public:
		GatewaySession(Samurai::EventLoop& loop, const UpnpOptions& options)
			: loop(loop), options(options) { }

		bool discover()
		{
			UPnP::Gateway::Options gwOptions;
			gwOptions.searchTimeout = options.searchTimeout;
			gwOptions.httpTimeout = options.actionTimeout;

			gateway = UPnP::Gateway::discover(loop, this, gwOptions);
			if (!gateway)
			{
				result.error = "the gateway search could not be started";
				return false;
			}

			/* The search timeout plus room for fetching the description, which
			   is a separate HTTP request to the device. */
			pump(loop, [&] { return finished; },
			     options.searchTimeout + options.actionTimeout);

			if (!result.gatewayFound)
			{
				if (result.error.empty())
					result.error = "no UPnP gateway answered";
				return false;
			}

			mapper = UPnP::PortMapper::create(loop, this, gateway.get(), mapperOptions());
			return mapper != nullptr;
		}

		/** Run one action and wait for it. */
		bool await()
		{
			finished = false;
			failed = false;
			pump(loop, [&] { return finished; }, options.actionTimeout);
			return finished && !failed;
		}

		UPnP::PortMapper::Options mapperOptions() const
		{
			UPnP::PortMapper::Options opts;
			opts.lease = options.lease;
			/* Many gateways refuse any lease with error 725; a permanent
			   mapping is better than no mapping. */
			opts.fallBackToPermanent = true;
			/* This process does not stay alive to renew, and a check that
			   leaves a renewal timer running would keep the loop busy long
			   after the answer was delivered. */
			opts.renewAutomatically = false;
			return opts;
		}

		UPnP::Gateway* getGateway() { return gateway.get(); }
		UPnP::PortMapper* getMapper() { return mapper.get(); }
		UpnpResult& getResult() { return result; }

	protected:
		void EventGatewayFound(UPnP::Gateway* gw) override
		{
			result.gatewayFound = true;
			result.gatewayName = gw->getFriendlyName();
			finished = true;
		}

		void EventGatewayError(UPnP::Gateway*, UPnP::Error error) override
		{
			result.error = UPnP::toString(error);
			finished = true;
		}

		void EventMappingAdded(UPnP::PortMapper*, const UPnP::Mapping& mapping) override
		{
			/* The granted port, which is not always the one asked for: a
			   conflict makes the mapper walk to the next, and that is the port
			   to delete later. */
			result.mappingAdded = true;
			if (mapping.protocol == UPnP::Protocol::TCP)
			{
				result.tcpExternalPort = mapping.externalPort;
				result.tcpInternalPort = mapping.internalPort;
			}
			else
			{
				result.udpExternalPort = mapping.externalPort;
				result.udpInternalPort = mapping.internalPort;
			}
			finished = true;
		}

		void EventMappingRemoved(UPnP::PortMapper*, const UPnP::MappingKey&) override
		{
			finished = true;
		}

		void EventExternalAddress(UPnP::PortMapper*,
		                          const Samurai::IO::Net::InetAddress& address) override
		{
			result.externalAddress = address.toString();
			finished = true;
		}

		void EventMapperError(UPnP::PortMapper*, UPnP::Error error,
		                      UPnP::DeviceError device, uint16_t code) override
		{
			result.error = UPnP::toString(error);
			if (error == UPnP::Error::Device)
			{
				result.error += ": ";
				result.error += UPnP::toString(device);
				if (code)
					result.error += " (" + std::to_string(code) + ")";
			}
			failed = true;
			finished = true;
		}

	private:
		Samurai::EventLoop& loop;
		UpnpOptions options;
		std::unique_ptr<UPnP::Gateway> gateway;
		std::unique_ptr<UPnP::PortMapper> mapper;
		UpnpResult result;
		bool finished = false;
		bool failed = false;
};

/**
 * Whether an IPv4 address is one that cannot be reached from the internet.
 *
 * Only enough to judge the gateway's own external address: RFC 1918, the
 * RFC 6598 shared range and loopback. A gateway reporting one of these has
 * another NAT above it.
 */
bool isPrivateV4(const std::string& text)
{
	unsigned a = 0, b = 0, c = 0, d = 0;
	if (sscanf(text.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return false;  /* not IPv4 at all; nothing claimed either way */

	if (a == 10 || a == 127) return true;
	if (a == 192 && b == 168) return true;
	if (a == 172 && b >= 16 && b <= 31) return true;
	if (a == 100 && b >= 64 && b <= 127) return true;  /* RFC 6598 */
	if (a == 169 && b == 254) return true;
	return false;
}

UPnP::Mapping makeMapping(UPnP::Protocol protocol, uint16_t external,
                          uint16_t internal_, const std::string& internalAddress,
                          const UpnpOptions& options)
{
	UPnP::Mapping mapping;
	mapping.protocol = protocol;
	mapping.externalPort = external;
	mapping.internalPort = internal_;
	mapping.description = options.description;
	mapping.lease = options.lease;
	mapping.enabled = true;
	if (!internalAddress.empty())
		mapping.internalClient = Samurai::IO::Net::InetAddress(internalAddress);
	return mapping;
}

} // namespace

bool Upnp::isApplicable(Family family)
{
	/*
	 * IGD forwards IPv4. An IPv6 host that cannot be reached has a firewall in
	 * the way rather than a NAT, and the IGD2 pinhole service that addresses
	 * that is rare enough not to be worth a search here - the honest answer is
	 * to tell the user to open the firewall.
	 */
	return family == Family::IPv4;
}

UpnpResult Upnp::addMapping(Samurai::EventLoop& loop, uint16_t tcpPort, uint16_t udpPort,
                            const std::string& internalAddress,
                            const Options& options)
{
	GatewaySession session(loop, options);

	if (!session.discover())
	{
		UpnpResult& result = session.getResult();
		result.summary = result.error.empty()
			? "No UPnP gateway was found."
			: "No usable UPnP gateway: " + result.error;
		return result;
	}

	UPnP::PortMapper* mapper = session.getMapper();
	UpnpResult& result = session.getResult();

	/* Asked for first, because it is the one thing a gateway can tell us that
	   the check cannot: a private address here means a second NAT upstream,
	   and no mapping on this device will ever be reachable. */
	mapper->getExternalAddress();
	session.await();

	if (tcpPort)
	{
		mapper->addMapping(makeMapping(UPnP::Protocol::TCP, tcpPort, tcpPort,
		                               internalAddress, options));
		if (!session.await())
		{
			result.summary = "The gateway refused a TCP mapping: " + result.error;
			return result;
		}
	}

	if (udpPort)
	{
		mapper->addMapping(makeMapping(UPnP::Protocol::UDP, udpPort, udpPort,
		                               internalAddress, options));
		if (!session.await())
		{
			/*
			 * The TCP mapping stands. Reporting the UDP failure rather than
			 * unwinding is the useful outcome: transfers will work and search
			 * results will not, which is a state the decision table has
			 * wording for.
			 */
			result.summary = "A TCP mapping was granted but the UDP one was "
			                 "refused: " + result.error;
			result.error.clear();
			return result;
		}
	}

	if (result.mappingAdded)
	{
		result.summary = "The gateway granted a mapping";
		if (!result.gatewayName.empty())
			result.summary += " (" + result.gatewayName + ")";
		result.summary += ". Whether it helps is what the second check decides.";

		/*
		 * A private external address is the one thing the gateway knows that
		 * the check cannot infer on its own: it means a second NAT upstream,
		 * so no mapping on this device can ever be reached.
		 */
		if (!result.externalAddress.empty() && isPrivateV4(result.externalAddress))
		{
			result.summary += " Note that the gateway's own external address is "
			                  + result.externalAddress + ", which is not a public "
			                  "address: there is another NAT upstream of it, and "
			                  "no mapping here can be reached from outside.";
		}
	}
	else if (result.summary.empty())
	{
		result.summary = "The gateway granted nothing.";
	}

	return result;
}

bool Upnp::removeMapping(Samurai::EventLoop& loop, uint16_t tcpPort, uint16_t udpPort,
                         const Options& options)
{
	GatewaySession session(loop, options);
	if (!session.discover())
		return false;

	UPnP::PortMapper* mapper = session.getMapper();
	bool ok = true;

	if (tcpPort)
	{
		UPnP::MappingKey key;
		key.protocol = UPnP::Protocol::TCP;
		key.externalPort = tcpPort;
		mapper->deleteMapping(key);
		ok = session.await() && ok;
	}
	if (udpPort)
	{
		UPnP::MappingKey key;
		key.protocol = UPnP::Protocol::UDP;
		key.externalPort = udpPort;
		mapper->deleteMapping(key);
		ok = session.await() && ok;
	}

	return ok;
}

}
