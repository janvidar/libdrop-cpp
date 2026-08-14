/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include "wire.h"

using Samurai::IO::JsonDocument;
using Samurai::IO::JsonError;
using Samurai::IO::JsonValue;
using Samurai::IO::JsonWriter;

namespace Drop {
namespace Wire {

namespace {

/** A port from a JSON number, refusing anything outside the range. */
uint16_t readPort(int64_t value)
{
	if (value < 0 || value > 65535)
		return 0;
	return static_cast<uint16_t>(value);
}

void readPortList(const JsonValue* array, std::vector<uint16_t>& out)
{
	if (!array || !array->isArray())
		return;
	for (size_t i = 0; i < array->size(); i++)
	{
		const JsonValue* entry = array->at(i);
		if (entry && entry->isNumber())
		{
			const uint16_t port = readPort(entry->getInteger());
			if (port) out.push_back(port);
		}
	}
}

void readStringList(const JsonValue* array, std::vector<std::string>& out)
{
	if (!array || !array->isArray())
		return;
	for (size_t i = 0; i < array->size(); i++)
	{
		const JsonValue* entry = array->at(i);
		if (entry && entry->isString())
			out.push_back(entry->getString());
	}
}

void readPortResults(const JsonValue* array, std::vector<PortResult>& out)
{
	if (!array || !array->isArray())
		return;
	for (size_t i = 0; i < array->size(); i++)
	{
		const JsonValue* entry = array->at(i);
		if (!entry || !entry->isObject())
			continue;

		PortResult result;
		result.port = readPort(entry->findInteger("port"));
		result.verdict = verdictFromString(entry->findString("verdict"));
		result.rttMs = static_cast<int>(entry->findInteger("rtt_ms"));
		result.respondedFrom = entry->findString("responded_from");
		result.detail = entry->findString("detail");
		out.push_back(std::move(result));
	}
}

ErrorInfo malformed(std::string_view what)
{
	ErrorInfo info;
	info.error = Error::Malformed;
	info.detail = std::string(what);
	return info;
}

} // namespace

bool parse(std::string_view text, JsonDocument& doc, ErrorInfo& out)
{
	const JsonError err = doc.parse(text);
	if (err != JsonError::Ok)
	{
		out = malformed(Samurai::IO::toString(err));
		return false;
	}
	if (!doc.getRoot() || !doc.getRoot()->isObject())
	{
		out = malformed("the response is not a JSON object");
		return false;
	}
	return true;
}

ErrorInfo readError(int status, std::string_view body, int retryAfterSeconds)
{
	ErrorInfo info;
	info.status = status;
	info.retryAfterSeconds = retryAfterSeconds;

	/*
	 * The status decides the category. The body only refines it, so a server
	 * that answered 429 with an empty body is still reported as rate limited
	 * rather than as an unreadable response.
	 */
	info.error = (status == 429) ? Error::RateLimited : Error::Server;

	JsonDocument doc;
	if (doc.parse(body) == JsonError::Ok && doc.getRoot() && doc.getRoot()->isObject())
	{
		info.code = doc.getRoot()->findString("error");
		info.detail = doc.getRoot()->findString("detail");
	}

	if (info.code.empty())
		info.code = "http_" + std::to_string(status);

	return info;
}

bool readServerInfo(const JsonValue& root, ServerInfo& out, ErrorInfo& err)
{
	out = ServerInfo();
	out.protocol = root.findString("protocol");

	/*
	 * The protocol marker is what tells a DROP server from a captive portal
	 * that answers 200 to everything, so it is checked before anything else is
	 * believed.
	 */
	if (out.protocol != "DROP/1")
	{
		err.error = Error::NotADropServer;
		err.detail = out.protocol.empty()
			? "the response carries no protocol marker"
			: "unexpected protocol \"" + out.protocol + "\"";
		return false;
	}

	out.name = root.findString("server");
	out.operatorName = root.findString("operator");
	out.abuseContact = root.findString("abuse_contact");

	if (const JsonValue* tests = root.find("tests"))
	{
		readStringList(tests->find("ipv4"), out.testsIPv4);
		readStringList(tests->find("ipv6"), out.testsIPv6);
	}

	if (const JsonValue* stun = root.find("stun"))
	{
		if (const JsonValue* primary = stun->find("primary"))
		{
			out.stunPrimaryIPv4 = primary->findString("ipv4");
			out.stunPrimaryIPv6 = primary->findString("ipv6");
			out.stunPrimaryPort = readPort(primary->findInteger("port"));
		}
		if (const JsonValue* alternate = stun->find("alternate"))
		{
			out.stunAlternateIPv4 = alternate->findString("ipv4");
			out.stunAlternateIPv6 = alternate->findString("ipv6");
			out.stunAlternatePort = readPort(alternate->findInteger("port"));
		}
	}

	if (const JsonValue* egress = root.find("egress"))
	{
		out.egressIPv4 = egress->findString("ipv4");
		out.egressIPv6 = egress->findString("ipv6");
		readPortList(egress->find("banner_ports"), out.egressBannerPorts);
		readPortList(egress->find("http_ports"), out.egressHttpPorts);
		readPortList(egress->find("https_ports"), out.egressHttpsPorts);
	}

	if (const JsonValue* limits = root.find("limits"))
	{
		out.maxPortsPerTest = static_cast<int>(limits->findInteger("max_ports_per_test"));
		out.minPort = static_cast<int>(limits->findInteger("min_port"));
		out.sessionsPerHour = static_cast<int>(limits->findInteger("sessions_per_hour"));
		out.probeTimeoutMs = static_cast<int>(limits->findInteger("probe_timeout_ms"));
		out.inboundDeadlineMs = static_cast<int>(limits->findInteger("inbound_deadline_ms"));
	}

	return true;
}

bool readWhoami(const JsonValue& root, Whoami& out, ErrorInfo& err)
{
	out = Whoami();
	out.ip = root.findString("ip");
	if (out.ip.empty())
	{
		err = malformed("the response carries no address");
		return false;
	}

	out.family = root.findString("family") == "ipv6" ? Family::IPv6 : Family::IPv4;
	out.port = readPort(root.findInteger("port"));
	out.classification = classificationFromString(root.findString("classification"));
	out.advice = root.findString("advice");
	return true;
}

bool readSession(const JsonValue& root, Family family, Session& out, ErrorInfo& err)
{
	out = Session();
	out.id = root.findString("session_id");
	if (out.id.empty())
	{
		err = malformed("the response carries no session id");
		return false;
	}

	out.expiresIn = static_cast<int>(root.findInteger("expires_in"));

	if (const JsonValue* observed = root.find("observed"))
	{
		out.observedIp = observed->findString("ip");
		out.observedPort = readPort(observed->findInteger("port"));
		out.classification = classificationFromString(observed->findString("classification"));
	}

	if (const JsonValue* creds = root.find("credentials"))
	{
		out.username = creds->findString("username");
		out.password = creds->findString("password");
	}

	/* Only this family's endpoints matter; the other family's are unreachable
	   from the socket that will use them. */
	const char* key = family == Family::IPv6 ? "ipv6" : "ipv4";
	if (const JsonValue* stun = root.find("stun"))
	{
		if (const JsonValue* primary = stun->find("primary"))
		{
			out.stunPrimary = primary->findString(key);
			out.stunPrimaryPort = readPort(primary->findInteger("port"));
		}
		if (const JsonValue* alternate = stun->find("alternate"))
		{
			out.stunAlternate = alternate->findString(key);
			out.stunAlternatePort = readPort(alternate->findInteger("port"));
		}
	}

	return true;
}

bool readInbound(const JsonValue& root, InboundResult& out, ErrorInfo& err)
{
	(void) err;
	out = InboundResult();
	out.sessionId = root.findString("session_id");
	out.elapsedMs = static_cast<int>(root.findInteger("elapsed_ms"));

	if (const JsonValue* observed = root.find("observed"))
	{
		out.observedIp = observed->findString("ip");
		out.observedPort = readPort(observed->findInteger("port"));
	}

	readPortResults(root.find("tcp"), out.tcp);
	readPortResults(root.find("udp"), out.udp);
	readStringList(root.find("notes"), out.notes);

	/*
	 * No membership check on tcp/udp: a server that ran only what it could is
	 * answering honestly, and the caller decides what a missing result means
	 * for the port it asked about. Inventing a verdict here would be worse.
	 */
	return true;
}

std::string writeSessionRequest(std::string_view userAgent,
                                const std::vector<std::string>& tests)
{
	JsonWriter w;
	w.beginObject();
	w.member("version", static_cast<int64_t>(1));
	if (!userAgent.empty())
		w.member("client", userAgent);
	if (!tests.empty())
	{
		w.member("tests").beginArray();
		for (const std::string& test : tests)
			w.value(test);
		w.endArray();
	}
	w.endObject();
	return w.str();
}

std::string writeInboundRequest(const std::vector<uint16_t>& tcp,
                                const std::vector<uint16_t>& udp,
                                uint16_t controlPort)
{
	JsonWriter w;
	w.beginObject();

	if (!tcp.empty())
	{
		w.member("tcp").beginArray();
		for (uint16_t port : tcp)
			w.value(static_cast<int64_t>(port));
		w.endArray();
	}
	if (!udp.empty())
	{
		w.member("udp").beginArray();
		for (uint16_t port : udp)
			w.value(static_cast<int64_t>(port));
		w.endArray();
	}
	if (controlPort)
		w.member("control_port", static_cast<int64_t>(controlPort));

	w.endObject();
	return w.str();
}

}
}
