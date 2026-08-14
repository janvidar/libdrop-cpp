/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_WIRE_H
#define HAVE_DROP_WIRE_H

#include <drop/types.h>

#include <samurai/io/json.h>

#include <string>
#include <string_view>
#include <vector>

/**
 * Translation between DROP's JSON and the types.
 *
 * Kept apart from the client so that every shape can be tested against a
 * captured document without a socket, which is the only way to have cases for
 * the responses a live server does not conveniently produce.
 */
namespace Drop {
namespace Wire {

/**
 * Parse a document.
 *
 * @return false with 'out' populated when the text is not JSON at all.
 */
bool parse(std::string_view text, Samurai::IO::JsonDocument& doc, ErrorInfo& out);

/**
 * Read an error body.
 *
 * A server that answered with a status but no recognisable body still yields a
 * usable ErrorInfo, since the status alone tells the caller most of it.
 */
ErrorInfo readError(int status, std::string_view body, int retryAfterSeconds);

bool readServerInfo(const Samurai::IO::JsonValue& root, ServerInfo& out, ErrorInfo& err);
bool readWhoami(const Samurai::IO::JsonValue& root, Whoami& out, ErrorInfo& err);
bool readSession(const Samurai::IO::JsonValue& root, Family family,
                 Session& out, ErrorInfo& err);
bool readInbound(const Samurai::IO::JsonValue& root, InboundResult& out, ErrorInfo& err);

/** The body of POST /v1/session. */
std::string writeSessionRequest(std::string_view userAgent,
                                const std::vector<std::string>& tests);

/**
 * The body of POST /v1/session/{id}/inbound.
 *
 * controlPort is the local source port of the control connection, which the
 * server compares against what it observed to detect source-port rewriting.
 * Zero omits it.
 */
std::string writeInboundRequest(const std::vector<uint16_t>& tcp,
                                const std::vector<uint16_t>& udp,
                                uint16_t controlPort);

}
}

#endif // HAVE_DROP_WIRE_H
