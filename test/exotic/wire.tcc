/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include "wire.h"

#include <drop/types.h>

#include <samurai/io/json.h>

#include <string>
#include <string_view>

/*
 * Reading what a server sent. The happy-path documents here are the ones the
 * live deployment actually returns, and the rest is what happens when a server
 * sends something else - which a client has to survive, since it does not
 * control what arrives.
 *
 * Every case is a string. Nothing here touches a socket, which is the point:
 * these are the shapes a live server does not conveniently produce on demand.
 */

namespace {

using namespace Drop;
using Samurai::IO::JsonDocument;
using Samurai::IO::JsonError;

/** Parse and hand back the root, or null. */
bool parse(JsonDocument& doc, std::string_view text)
{
	return doc.parse(text) == JsonError::Ok && doc.getRoot() != nullptr;
}

/* Captured from drop.quickdc.org. */
const char* SERVER_DOC = R"({
  "protocol": "DROP/1",
  "server": "drop.quickdc.org",
  "operator": "quickdc.org",
  "abuse_contact": "abuse@quickdc.org",
  "tests": {
    "ipv4": ["tcp", "udp", "egress"],
    "ipv6": ["tcp", "udp", "egress", "nat"]
  },
  "stun": {
    "primary": { "ipv4": "201.79.4.56", "ipv6": "2a03:b0c0:3:f0:0:2:ce4c:7000",
                 "port": 3478 },
    "alternate": { "ipv6": "2a03:b0c0:3:f0:0:2:ce4c:7001", "port": 3479 }
  },
  "egress": {
    "ipv4": "201.79.4.56",
    "ipv6": "2a03:b0c0:3:f0:0:2:ce4c:7000",
    "banner_ports": [411, 412, 1511, 5000],
    "http_ports": [80],
    "https_ports": [443]
  },
  "limits": {
    "max_ports_per_test": 4, "min_port": 1024, "sessions_per_hour": 12,
    "probe_timeout_ms": 5000, "inbound_deadline_ms": 15000
  }
})";

} // namespace

EXO_TEST(wire_reads_the_capability_document, {
	JsonDocument doc;
	if (!parse(doc, SERVER_DOC)) return false;

	ServerInfo info;
	ErrorInfo err;
	if (!Wire::readServerInfo(*doc.getRoot(), info, err)) return false;

	return info.protocol == "DROP/1"
	    && info.name == "drop.quickdc.org"
	    && info.abuseContact == "abuse@quickdc.org"
	    && info.stunPrimaryIPv4 == "201.79.4.56"
	    && info.stunPrimaryPort == 3478
	    && info.stunAlternatePort == 3479
	    && info.egressBannerPorts.size() == 4
	    && info.egressBannerPorts[0] == 411
	    && info.maxPortsPerTest == 4
	    && info.minPort == 1024;
});

EXO_TEST(wire_capabilities_are_read_per_family, {
	/*
	 * The two lists routinely differ - a second IPv6 address is normally free
	 * and a second IPv4 one is not - so inferring either from the other is how
	 * a client asks for a test the server cannot run.
	 */
	JsonDocument doc;
	if (!parse(doc, SERVER_DOC)) return false;

	ServerInfo info;
	ErrorInfo err;
	if (!Wire::readServerInfo(*doc.getRoot(), info, err)) return false;

	return info.supports(Family::IPv4, "tcp")
	    && info.supports(Family::IPv4, "udp")
	    && !info.supports(Family::IPv4, "nat")   /* one address only */
	    && info.supports(Family::IPv6, "nat")
	    && !info.supports(Family::IPv4, "invented");
});

EXO_TEST(wire_refuses_a_peer_that_is_not_a_drop_server, {
	/* The protocol marker is what tells a DROP server from a captive portal
	   that answers 200 to everything. */
	const char* cases[] = {
		R"({"protocol":"HTTP/1.1","server":"x"})",
		R"({"server":"x"})",
		R"({"protocol":"DROP/2"})",
		R"({})",
	};

	for (const char* text : cases)
	{
		JsonDocument doc;
		if (!parse(doc, text)) return false;

		ServerInfo info;
		ErrorInfo err;
		if (Wire::readServerInfo(*doc.getRoot(), info, err))
			return false;
		if (err.error != Error::NotADropServer)
			return false;
	}
	return true;
});

EXO_TEST(wire_reads_whoami, {
	JsonDocument doc;
	if (!parse(doc, R"({"ip":"81.191.239.108","family":"ipv4","port":51343,
	                    "classification":"global","advice":"Ordinary public address.",
	                    "observed_at":"2026-08-14T12:00:00Z"})"))
		return false;

	Whoami who;
	ErrorInfo err;
	if (!Wire::readWhoami(*doc.getRoot(), who, err)) return false;

	return who.ip == "81.191.239.108"
	    && who.family == Family::IPv4
	    && who.port == 51343
	    && who.classification == Classification::Global
	    && who.advice == "Ordinary public address.";
});

EXO_TEST(wire_reads_every_classification, {
	struct Case { const char* text; Classification expected; };
	const Case cases[] = {
		{ "global",       Classification::Global },
		{ "cgnat",        Classification::CGNAT },
		{ "private",      Classification::Private },
		{ "unique-local", Classification::UniqueLocal },
		{ "loopback",     Classification::Loopback },
		{ "teredo",       Classification::Teredo },
		{ "6to4",         Classification::SixToFour },
		{ "link-local",   Classification::LinkLocal },
		/* A server that grows a new one must not be misread as a known one. */
		{ "something-new", Classification::Unknown },
	};

	for (const Case& c : cases)
	{
		if (classificationFromString(c.text) != c.expected)
			return false;
	}
	return true;
});

EXO_TEST(wire_whoami_without_an_address_is_malformed, {
	JsonDocument doc;
	if (!parse(doc, R"({"family":"ipv4"})")) return false;

	Whoami who;
	ErrorInfo err;
	return !Wire::readWhoami(*doc.getRoot(), who, err)
	    && err.error == Error::Malformed;
});

EXO_TEST(wire_reads_a_session_for_the_right_family, {
	const char* text = R"({
	  "session_id": "abc.def", "expires_in": 60,
	  "observed": { "ip": "81.191.239.108", "port": 51343, "classification": "global" },
	  "stun": { "primary":   { "ipv4": "198.51.100.10", "ipv6": "2001:db8::10", "port": 3478 },
	            "alternate": { "ipv4": "198.51.100.11", "ipv6": "2001:db8::11", "port": 3479 } },
	  "credentials": { "username": "abc.def", "password": "secret" }
	})";

	JsonDocument doc;
	if (!parse(doc, text)) return false;

	Session v4;
	Session v6;
	ErrorInfo err;
	if (!Wire::readSession(*doc.getRoot(), Family::IPv4, v4, err)) return false;
	if (!Wire::readSession(*doc.getRoot(), Family::IPv6, v6, err)) return false;

	/* Only this family's endpoints: the other family's are unreachable from
	   the socket that would use them. */
	return v4.id == "abc.def"
	    && v4.password == "secret"
	    && v4.observedPort == 51343
	    && v4.stunPrimary == "198.51.100.10"
	    && v4.stunAlternate == "198.51.100.11"
	    && v6.stunPrimary == "2001:db8::10"
	    && v6.stunAlternate == "2001:db8::11";
});

EXO_TEST(wire_session_without_an_id_is_malformed, {
	JsonDocument doc;
	if (!parse(doc, R"({"expires_in":60})")) return false;

	Session session;
	ErrorInfo err;
	return !Wire::readSession(*doc.getRoot(), Family::IPv4, session, err)
	    && err.error == Error::Malformed;
});

EXO_TEST(wire_reads_inbound_results, {
	const char* text = R"({
	  "session_id": "abc.def",
	  "observed": { "ip": "81.191.239.108", "port": 51343 },
	  "tcp": [ { "port": 1511, "verdict": "open", "rtt_ms": 31 },
	           { "port": 1512, "verdict": "refused" } ],
	  "udp": [ { "port": 1511, "verdict": "open",
	             "responded_from": "81.191.239.108:1511" } ],
	  "notes": [ "a note", "another" ],
	  "elapsed_ms": 3120
	})";

	JsonDocument doc;
	if (!parse(doc, text)) return false;

	InboundResult result;
	ErrorInfo err;
	if (!Wire::readInbound(*doc.getRoot(), result, err)) return false;

	const PortResult* open = result.findTcp(1511);
	const PortResult* refused = result.findTcp(1512);

	return result.tcp.size() == 2
	    && result.udp.size() == 1
	    && result.notes.size() == 2
	    && result.elapsedMs == 3120
	    && open && open->verdict == Verdict::Open && open->rttMs == 31
	    && refused && refused->verdict == Verdict::Refused
	    && result.findUdp(1511)->respondedFrom == "81.191.239.108:1511"
	    /* A port that was not tested is absent, not a fabricated verdict. */
	    && result.findTcp(9999) == nullptr;
});

EXO_TEST(wire_reads_every_verdict, {
	struct Case { const char* text; Verdict expected; };
	const Case cases[] = {
		{ "open",        Verdict::Open },
		{ "occupied",    Verdict::Occupied },
		{ "refused",     Verdict::Refused },
		{ "filtered",    Verdict::Filtered },
		{ "no_response", Verdict::NoResponse },
		{ "error",       Verdict::Error },
		{ "invented",    Verdict::Unknown },
	};

	for (const Case& c : cases)
	{
		if (verdictFromString(c.text) != c.expected)
			return false;
	}
	return true;
});

EXO_TEST(wire_survives_wrong_types_throughout, {
	/*
	 * A client does not control what arrives. Every field here is the wrong
	 * type; the reader must produce something harmless rather than crash or
	 * invent a plausible value.
	 */
	const char* text = R"({
	  "protocol": "DROP/1",
	  "server": 42,
	  "tests": "not an object",
	  "stun": [1, 2, 3],
	  "egress": { "banner_ports": ["not a number", 411, {}, null] },
	  "limits": { "min_port": "1024" }
	})";

	JsonDocument doc;
	if (!parse(doc, text)) return false;

	ServerInfo info;
	ErrorInfo err;
	if (!Wire::readServerInfo(*doc.getRoot(), info, err)) return false;

	return info.name.empty()             /* a number is not a name */
	    && info.testsIPv4.empty()
	    && info.egressBannerPorts.size() == 1  /* only the real one survived */
	    && info.egressBannerPorts[0] == 411
	    && info.minPort == 0;            /* a string is not a port */
});

EXO_TEST(wire_refuses_out_of_range_ports, {
	/* A port outside the range is dropped rather than truncated into a
	   different, valid-looking port. */
	JsonDocument doc;
	if (!parse(doc, R"({"tcp":[{"port":70000,"verdict":"open"},
	                          {"port":-1,"verdict":"open"},
	                          {"port":1511,"verdict":"open"}]})"))
		return false;

	InboundResult result;
	ErrorInfo err;
	if (!Wire::readInbound(*doc.getRoot(), result, err)) return false;

	return result.tcp.size() == 3
	    && result.tcp[0].port == 0
	    && result.tcp[1].port == 0
	    && result.tcp[2].port == 1511;
});

EXO_TEST(wire_reads_an_error_body, {
	const ErrorInfo info = Wire::readError(409,
		R"({"error":"session_already_ran","detail":"open a new session"})", 0);

	return info.error == Error::Server
	    && info.status == 409
	    && info.code == "session_already_ran"
	    && info.detail == "open a new session"
	    && !info.message().empty();
});

EXO_TEST(wire_a_429_is_rate_limiting_whatever_the_body_says, {
	/* The status decides the category; the body only refines it. A server
	   that answered 429 with nothing is still rate limiting. */
	const ErrorInfo withBody = Wire::readError(429, R"({"error":"rate_limited"})", 196);
	const ErrorInfo empty = Wire::readError(429, "", 30);
	const ErrorInfo garbage = Wire::readError(429, "<html>go away</html>", 0);

	return withBody.error == Error::RateLimited
	    && withBody.retryAfterSeconds == 196
	    && empty.error == Error::RateLimited
	    && empty.retryAfterSeconds == 30
	    && garbage.error == Error::RateLimited
	    /* An unreadable body still yields a usable code. */
	    && garbage.code == "http_429";
});

EXO_TEST(wire_an_unreadable_error_body_still_reports_the_status, {
	const ErrorInfo info = Wire::readError(503, "not json at all", 0);
	return info.error == Error::Server && info.status == 503
	    && info.code == "http_503";
});

EXO_TEST(wire_rejects_a_response_that_is_not_an_object, {
	const char* cases[] = { "[1,2,3]", "\"text\"", "42", "null", "not json" };

	for (const char* text : cases)
	{
		JsonDocument doc;
		ErrorInfo err;
		if (Wire::parse(text, doc, err))
			return false;
		if (err.error != Error::Malformed)
			return false;
	}
	return true;
});

/* --- writing -------------------------------------------------------------- */

EXO_TEST(wire_writes_a_session_request, {
	const std::string body = Wire::writeSessionRequest("dropcheck/1.0", {});

	JsonDocument doc;
	if (!parse(doc, body)) return false;

	return doc.getRoot()->findInteger("version") == 1
	    && doc.getRoot()->findString("client") == "dropcheck/1.0";
});

EXO_TEST(wire_writes_the_requested_tests, {
	const std::string body =
		Wire::writeSessionRequest("x", { "tcp", "udp", "nat" });

	JsonDocument doc;
	if (!parse(doc, body)) return false;

	const Samurai::IO::JsonValue* tests = doc.getRoot()->find("tests");
	return tests && tests->isArray() && tests->size() == 3
	    && tests->at(0)->getString() == "tcp"
	    && tests->at(2)->getString() == "nat";
});

EXO_TEST(wire_writes_an_inbound_request, {
	const std::string body =
		Wire::writeInboundRequest({ 1511, 1512 }, { 1511 }, 51343);

	JsonDocument doc;
	if (!parse(doc, body)) return false;

	const Samurai::IO::JsonValue* root = doc.getRoot();
	const Samurai::IO::JsonValue* tcp = root->find("tcp");

	return tcp && tcp->size() == 2
	    && tcp->at(0)->getInteger() == 1511
	    && root->find("udp")->size() == 1
	    && root->findInteger("control_port") == 51343;
});

EXO_TEST(wire_omits_what_was_not_asked_for, {
	/* An absent control_port is not the same as zero, and an empty port list
	   should not appear at all. */
	const std::string body = Wire::writeInboundRequest({ 1511 }, {}, 0);

	JsonDocument doc;
	if (!parse(doc, body)) return false;

	return doc.getRoot()->find("tcp") != nullptr
	    && doc.getRoot()->find("udp") == nullptr
	    && doc.getRoot()->find("control_port") == nullptr;
});

EXO_TEST(wire_never_writes_a_target_address, {
	/*
	 * The structural rule of the whole protocol: the server probes the source
	 * of the control connection and nothing else. A request body that could
	 * name an address would make this an aimable port scanner, so no request
	 * this library builds may contain anything resembling one.
	 */
	const std::string bodies[] = {
		Wire::writeSessionRequest("client", { "tcp", "udp" }),
		Wire::writeInboundRequest({ 1511 }, { 1511 }, 51343),
	};

	const char* banned[] = { "ip", "addr", "address", "host", "target",
	                         "peer", "dest" };

	for (const std::string& body : bodies)
	{
		for (const char* needle : banned)
		{
			if (body.find(std::string("\"") + needle) != std::string::npos)
				return false;
		}
	}
	return true;
});

EXO_TEST(wire_round_trips_a_request_through_the_reader, {
	/* What this writes, a conforming reader must accept. */
	const std::string body = Wire::writeInboundRequest({ 1511 }, { 1512 }, 40000);

	JsonDocument doc;
	return parse(doc, body) && doc.getRoot()->isObject();
});
