/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/types.h>

namespace Drop {

const char* toString(Family family)
{
	return family == Family::IPv6 ? "ipv6" : "ipv4";
}

Classification classificationFromString(std::string_view text)
{
	if (text == "global")       return Classification::Global;
	if (text == "cgnat")        return Classification::CGNAT;
	if (text == "private")      return Classification::Private;
	if (text == "unique-local") return Classification::UniqueLocal;
	if (text == "loopback")     return Classification::Loopback;
	if (text == "teredo")       return Classification::Teredo;
	if (text == "6to4")         return Classification::SixToFour;
	if (text == "link-local")   return Classification::LinkLocal;
	return Classification::Unknown;
}

const char* toString(Classification classification)
{
	switch (classification)
	{
		case Classification::Global:      return "global";
		case Classification::CGNAT:       return "cgnat";
		case Classification::Private:     return "private";
		case Classification::UniqueLocal: return "unique-local";
		case Classification::Loopback:    return "loopback";
		case Classification::Teredo:      return "teredo";
		case Classification::SixToFour:   return "6to4";
		case Classification::LinkLocal:   return "link-local";
		case Classification::Unknown:     break;
	}
	return "unknown";
}

bool isRoutable(Classification classification)
{
	switch (classification)
	{
		case Classification::Global:
		case Classification::Teredo:
		case Classification::SixToFour:
			return true;
		default:
			return false;
	}
}

Verdict verdictFromString(std::string_view text)
{
	if (text == "open")        return Verdict::Open;
	if (text == "occupied")    return Verdict::Occupied;
	if (text == "refused")     return Verdict::Refused;
	if (text == "filtered")    return Verdict::Filtered;
	if (text == "no_response") return Verdict::NoResponse;
	if (text == "error")       return Verdict::Error;
	return Verdict::Unknown;
}

const char* toString(Verdict verdict)
{
	switch (verdict)
	{
		case Verdict::Open:       return "open";
		case Verdict::Occupied:   return "occupied";
		case Verdict::Refused:    return "refused";
		case Verdict::Filtered:   return "filtered";
		case Verdict::NoResponse: return "no_response";
		case Verdict::Error:      return "error";
		case Verdict::Unknown:    break;
	}
	return "unknown";
}

const char* toString(Behaviour behaviour)
{
	switch (behaviour)
	{
		case Behaviour::None:                    return "none";
		case Behaviour::Blocked:                 return "blocked";
		case Behaviour::EndpointIndependent:     return "endpoint-independent";
		case Behaviour::AddressDependent:        return "address-dependent";
		case Behaviour::AddressAndPortDependent: return "address-and-port-dependent";
		case Behaviour::Unknown:                 break;
	}
	return "unknown";
}

const char* toString(Mode mode)
{
	switch (mode)
	{
		case Mode::Active:  return "active";
		case Mode::Passive: return "passive";
		case Mode::Unknown: break;
	}
	return "unknown";
}

const char* toString(Error error)
{
	switch (error)
	{
		case Error::Ok:             return "ok";
		case Error::InvalidUrl:     return "invalid url";
		case Error::Transport:      return "the server could not be reached";
		case Error::Malformed:      return "the response could not be understood";
		case Error::NotADropServer: return "the peer is not a DROP server";
		case Error::Server:         return "the server refused the request";
		case Error::RateLimited:    return "rate limited";
		case Error::Local:          return "a local socket could not be prepared";
		case Error::Unsupported:    return "not supported";
	}
	return "unknown error";
}

std::string ErrorInfo::message() const
{
	std::string out = toString(error);
	if (!code.empty())
	{
		out += ": ";
		out += code;
	}
	if (!detail.empty())
	{
		out += code.empty() ? ": " : " (";
		out += detail;
		if (!code.empty()) out += ")";
	}
	return out;
}

bool NatResult::holePunchLikely() const
{
	if (mapping == Behaviour::None)
		return true;
	if (mapping != Behaviour::EndpointIndependent)
		return false;
	return filtering == Behaviour::EndpointIndependent
	    || filtering == Behaviour::AddressDependent;
}

std::string NatResult::summary() const
{
	if (mapping == Behaviour::Blocked)
	{
		return "Outbound UDP is blocked entirely. UDP search results cannot "
		       "work on this network.";
	}
	if (mapping == Behaviour::None)
		return "No NAT is in the path.";
	if (mapping == Behaviour::Unknown)
	{
		return "Your NAT's behaviour could not be determined, so nothing can "
		       "be said about hole punching.";
	}
	if (holePunchLikely())
	{
		return "Your NAT is well behaved: hole punching has a good chance of "
		       "working with other clients.";
	}
	return "Your NAT assigns a different external port per destination, so "
	       "hole punching will not work reliably. A forwarded port is the only "
	       "dependable option.";
}

bool ServerInfo::supports(Family family, std::string_view test) const
{
	const std::vector<std::string>& tests =
		family == Family::IPv6 ? testsIPv6 : testsIPv4;
	for (const std::string& entry : tests)
	{
		if (entry == test)
			return true;
	}
	return false;
}

static const PortResult* findPort(const std::vector<PortResult>& list, uint16_t port)
{
	for (const PortResult& result : list)
	{
		if (result.port == port)
			return &result;
	}
	return nullptr;
}

const PortResult* InboundResult::findTcp(uint16_t port) const
{
	return findPort(tcp, port);
}

const PortResult* InboundResult::findUdp(uint16_t port) const
{
	return findPort(udp, port);
}

}
