/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/client.h>

#include "wire.h"

#include <samurai/io/net/socketaddress.h>
#include <samurai/io/net/url.h>

#include <stdlib.h>

#include <optional>
#include <string_view>

using Samurai::IO::JsonDocument;
using Samurai::IO::Net::URL;

namespace HTTP = Samurai::IO::Net::HTTP;

namespace Drop {

namespace {

std::string trimSlash(std::string url)
{
	while (!url.empty() && url.back() == '/')
		url.pop_back();
	return url;
}

/** Retry-After, which a 429 carries and nothing else needs. */
int retryAfterOf(const HTTP::Response& response)
{
	const std::optional<std::string_view> field =
		response.getHeaders().get("Retry-After");
	if (!field || field->empty())
		return 0;
	const std::string value(*field);
	const long seconds = strtol(value.c_str(), nullptr, 10);
	return (seconds > 0 && seconds < 86400) ? static_cast<int>(seconds) : 0;
}

} // namespace

Client::Client(ClientEventHandler* eh, std::string baseUrl, Family family)
	: Client(eh, std::move(baseUrl), family, Options())
{
}

Client::Client(ClientEventHandler* eh, std::string baseUrl, Family family,
               const Options& options)
	: eventHandler(eh)
	, base_url(trimSlash(std::move(baseUrl)))
	, family(family)
	, options(options)
{
}

Client::~Client() = default;

bool Client::isBusy() const
{
	return pending != Pending::None;
}

void Client::abort()
{
	pending = Pending::None;
	if (http) http->abort();
	http.reset();
}

void Client::internal_fail(const ErrorInfo& info)
{
	pending = Pending::None;
	if (eventHandler) eventHandler->EventDropError(this, info);
}

void Client::internal_prepare(std::chrono::milliseconds timeout)
{
	HTTP::Client::Options opts;
	opts.timeout = timeout;
	opts.userAgent = options.userAgent;
	opts.allowUntrustedCertificate = options.allowUntrustedCertificate;
	opts.localAddress = options.localAddress;
	/* A redirect would take the session credentials somewhere the caller never
	   named, so none is followed. */
	opts.maxRedirects = 0;

	http = std::make_unique<HTTP::Client>(this, opts);
}

void Client::internal_get(Pending what, const std::string& path)
{
	if (isBusy())
	{
		ErrorInfo info;
		info.error = Error::Unsupported;
		info.detail = "a request is already in flight";
		internal_fail(info);
		return;
	}

	const URL url(base_url + path);
	if (!url.isValid() || url.getScheme() != "https")
	{
		ErrorInfo info;
		info.error = Error::InvalidUrl;
		info.detail = "the base URL must be https";
		internal_fail(info);
		return;
	}

	pending = what;
	internal_prepare(options.timeout);
	http->get(url);
}

void Client::internal_post(Pending what, const std::string& path,
                           const std::string& body,
                           std::chrono::milliseconds timeout)
{
	if (isBusy())
	{
		ErrorInfo info;
		info.error = Error::Unsupported;
		info.detail = "a request is already in flight";
		internal_fail(info);
		return;
	}
	if (body.empty())
	{
		/* JsonWriter yields an empty string when it was misused, so an empty
		   body here is a bug on this side rather than something to send. */
		ErrorInfo info;
		info.error = Error::Malformed;
		info.detail = "the request body could not be built";
		internal_fail(info);
		return;
	}

	const URL url(base_url + path);
	if (!url.isValid() || url.getScheme() != "https")
	{
		ErrorInfo info;
		info.error = Error::InvalidUrl;
		info.detail = "the base URL must be https";
		internal_fail(info);
		return;
	}

	pending = what;
	internal_prepare(timeout);
	http->post(url, "application/json", body);
}

void Client::requestServerInfo()
{
	internal_get(Pending::ServerInfo, "/v1/server");
}

void Client::requestWhoami()
{
	internal_get(Pending::Whoami, "/v1/whoami");
}

void Client::openSession(const std::vector<std::string>& tests)
{
	internal_post(Pending::Session, "/v1/session",
	              Wire::writeSessionRequest(options.userAgent, tests),
	              options.timeout);
}

void Client::requestInbound(const Session& session,
                            const std::vector<uint16_t>& tcpPorts,
                            const std::vector<uint16_t>& udpPorts)
{
	if (session.id.empty())
	{
		ErrorInfo info;
		info.error = Error::Unsupported;
		info.detail = "no session";
		internal_fail(info);
		return;
	}

	internal_post(Pending::Inbound, "/v1/session/" + session.id + "/inbound",
	              Wire::writeInboundRequest(tcpPorts, udpPorts, control_port),
	              options.inboundTimeout);
}

void Client::EventHttpError(HTTP::Client*, HTTP::Status status, const char* msg)
{
	ErrorInfo info;
	info.error = (status == HTTP::Status::InvalidUrl)
		? Error::InvalidUrl : Error::Transport;
	info.detail = msg ? msg : "";
	internal_fail(info);
}

void Client::EventHttpResponse(HTTP::Client* client, const HTTP::Response& response)
{
	const Pending what = pending;
	pending = Pending::None;

	/*
	 * Where this connection went out from. The next request reports the port
	 * as control_port, which the server compares against the port it observed;
	 * a difference means a NAT is rewriting source ports. Both are read from
	 * the HTTP client rather than from its socket, which is already closed by
	 * the time a response is delivered.
	 */
	if (const Samurai::IO::Net::InetAddress* local = client->getLocalAddress())
		control_address = local->toString();
	if (const uint16_t port = client->getLocalPort())
		control_port = port;

	const int status = response.getStatusCode();
	if (status < 200 || status > 299)
	{
		internal_fail(Wire::readError(status, response.getBody(),
		                              retryAfterOf(response)));
		return;
	}

	JsonDocument doc;
	ErrorInfo err;
	if (!Wire::parse(response.getBody(), doc, err))
	{
		internal_fail(err);
		return;
	}

	const Samurai::IO::JsonValue& root = *doc.getRoot();

	switch (what)
	{
		case Pending::ServerInfo:
		{
			ServerInfo info;
			if (!Wire::readServerInfo(root, info, err)) { internal_fail(err); return; }
			if (eventHandler) eventHandler->EventDropServerInfo(this, info);
			return;
		}
		case Pending::Whoami:
		{
			Whoami who;
			if (!Wire::readWhoami(root, who, err)) { internal_fail(err); return; }
			if (eventHandler) eventHandler->EventDropWhoami(this, who);
			return;
		}
		case Pending::Session:
		{
			Session session;
			if (!Wire::readSession(root, family, session, err)) { internal_fail(err); return; }
			if (eventHandler) eventHandler->EventDropSession(this, session);
			return;
		}
		case Pending::Inbound:
		{
			InboundResult result;
			if (!Wire::readInbound(root, result, err)) { internal_fail(err); return; }
			if (eventHandler) eventHandler->EventDropInbound(this, result);
			return;
		}
		case Pending::None:
			/* A response with nothing outstanding: the request was aborted
			   between the answer arriving and this running. Say nothing. */
			return;
	}
}

}
