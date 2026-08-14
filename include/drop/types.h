/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_TYPES_H
#define HAVE_DROP_TYPES_H

#include <stdint.h>
#include <optional>
#include <string>
#include <vector>

/**
 * A client for DROP, the Diagnostic Reachability & Obstacle Probe.
 *
 * DROP answers two questions a peer-to-peer client cannot answer alone: what
 * its public addresses are, and whether anything can actually reach it on
 * them. See doc/drop.txt for the protocol.
 */
namespace Drop {

/** Which address family a run tests. One connection has one source address. */
enum class Family { IPv4, IPv6 };

const char* toString(Family family);

/** How the observed address is classified, from /v1/whoami. */
enum class Classification
{
	Unknown,
	Global,
	CGNAT,        /**< 100.64.0.0/10; a shared address, so no forward can work */
	Private,
	UniqueLocal,
	Loopback,
	Teredo,
	SixToFour,
	LinkLocal
};

Classification classificationFromString(std::string_view text);
const char* toString(Classification classification);

/** Whether a client at an address of this class could ever be reached. */
bool isRoutable(Classification classification);

/** The outcome of probing one port. */
enum class Verdict
{
	Unknown,
	/** Connected and the nonce came back. Active mode works. */
	Open,
	/** Something is listening, but it is not this client. */
	Occupied,
	/** RST or ICMP unreachable: reachable, nothing listening, nothing dropped. */
	Refused,
	/** Timeout. A firewall or NAT is silently dropping. */
	Filtered,
	/** UDP only: nothing came back, which is blocked or not implemented. */
	NoResponse,
	/** The server could not perform the probe. Not a statement about the client. */
	Error
};

Verdict verdictFromString(std::string_view text);
const char* toString(Verdict verdict);

/** One port's result. */
struct PortResult
{
	uint16_t port = 0;
	Verdict verdict = Verdict::Unknown;
	int rttMs = 0;
	std::string respondedFrom;
	std::string detail;
};

/** RFC 4787 behaviour, as classified by RFC 5780 tests. */
enum class Behaviour
{
	Unknown,
	None,                     /**< the mapped address is our own; no NAT */
	Blocked,                  /**< nothing answered; outbound UDP does not leave */
	EndpointIndependent,
	AddressDependent,
	AddressAndPortDependent
};

const char* toString(Behaviour behaviour);

/** What NAT behaviour discovery established. */
struct NatResult
{
	Behaviour mapping = Behaviour::Unknown;
	Behaviour filtering = Behaviour::Unknown;
	bool portPreserving = false;

	std::string localAddress;
	std::string mappedAddress;
	std::string otherAddress;

	std::vector<std::string> notes;

	/**
	 * Whether hole punching, and so ADC's NATT extension, has a realistic
	 * chance. Says nothing about whether strangers can reach the client: every
	 * request in behaviour discovery is client-initiated.
	 */
	bool holePunchLikely() const;

	/** A sentence for the user, so every client says the same thing. */
	std::string summary() const;
};

/** What the client should do about its ADC advertisement. */
enum class Mode
{
	/** Advertise the TCP4/TCP6 feature token and the U4/U6 port. */
	Active,
	/** Advertise neither. */
	Passive,
	/** Nothing could be established; do not change existing settings. */
	Unknown
};

const char* toString(Mode mode);

/** The conclusion for one address family. */
struct Decision
{
	Family family = Family::IPv4;
	Mode mode = Mode::Unknown;

	/** The port to advertise in U4/U6, when active. */
	uint16_t advertisePort = 0;

	/** One line to show the user. */
	std::string reason;
	/** Concrete next steps, in the order worth trying. */
	std::vector<std::string> remedies;
	/** An extra observation, such as the hole-punching prognosis. */
	std::string note;

	Verdict tcp = Verdict::Unknown;
	Verdict udp = Verdict::Unknown;
};

/** One egress port's outcome. */
struct EgressResult
{
	uint16_t port = 0;
	bool reached = false;
	std::string detail;
};

/** What the server advertises about itself. */
struct ServerInfo
{
	std::string protocol;
	std::string name;
	std::string operatorName;
	std::string abuseContact;

	/** Per family, because the two lists routinely differ. */
	std::vector<std::string> testsIPv4;
	std::vector<std::string> testsIPv6;

	std::string stunPrimaryIPv4;
	std::string stunPrimaryIPv6;
	uint16_t stunPrimaryPort = 0;
	std::string stunAlternateIPv4;
	std::string stunAlternateIPv6;
	uint16_t stunAlternatePort = 0;

	std::string egressIPv4;
	std::string egressIPv6;
	std::vector<uint16_t> egressBannerPorts;
	std::vector<uint16_t> egressHttpPorts;
	std::vector<uint16_t> egressHttpsPorts;

	int maxPortsPerTest = 0;
	int minPort = 0;
	int sessionsPerHour = 0;
	int probeTimeoutMs = 0;
	int inboundDeadlineMs = 0;

	bool supports(Family family, std::string_view test) const;
};

/** The reflexive address, from /v1/whoami. */
struct Whoami
{
	std::string ip;
	Family family = Family::IPv4;
	uint16_t port = 0;
	Classification classification = Classification::Unknown;
	/** The server's own wording for the classification. */
	std::string advice;
};

/** An issued session. */
struct Session
{
	std::string id;
	int expiresIn = 0;

	std::string observedIp;
	uint16_t observedPort = 0;
	Classification classification = Classification::Unknown;

	/** RFC 8489 short-term credentials for the UDP tests. */
	std::string username;
	std::string password;

	std::string stunPrimary;      /**< host:port for this session's family */
	uint16_t stunPrimaryPort = 0;
	std::string stunAlternate;
	uint16_t stunAlternatePort = 0;
};

/** The result of the inbound probes. */
struct InboundResult
{
	std::string sessionId;
	std::string observedIp;
	uint16_t observedPort = 0;
	std::vector<PortResult> tcp;
	std::vector<PortResult> udp;
	std::vector<std::string> notes;
	int elapsedMs = 0;

	const PortResult* findTcp(uint16_t port) const;
	const PortResult* findUdp(uint16_t port) const;
};

/** Why a request failed. */
enum class Error
{
	Ok,
	/** The URL was rejected, or the scheme is not https. */
	InvalidUrl,
	/** No answer, TLS failure, or the connection was refused. */
	Transport,
	/** The response was not JSON, or not the shape expected. */
	Malformed,
	/** The peer answered, but not as a DROP server. */
	NotADropServer,
	/** A 4xx or 5xx, with the server's own code in ErrorInfo::code. */
	Server,
	/** Rate limited, with the wait in ErrorInfo::retryAfterSeconds. */
	RateLimited,
	/** A local socket could not be opened or bound. */
	Local,
	/** The caller asked for something this build or that server cannot do. */
	Unsupported
};

const char* toString(Error error);

/** What went wrong, in enough detail to act on. */
struct ErrorInfo
{
	Error error = Error::Ok;
	/** The HTTP status, when there was one. */
	int status = 0;
	/** The server's machine-readable code, such as "session_already_ran". */
	std::string code;
	std::string detail;
	int retryAfterSeconds = 0;

	bool ok() const { return error == Error::Ok; }
	std::string message() const;
};

/**
 * Apply the specification's decision table.
 *
 * In one place on purpose. A user who moves between two clients and gets two
 * different explanations of the same network concludes one of them is broken,
 * and the way to prevent that is for there to be one table rather than one per
 * client.
 *
 * @param tcp the TCP result, or null when none was obtained.
 * @param udp the UDP result, or null when none was obtained.
 * @param tcpPort the port to advertise if the verdict is active.
 */
Decision decide(Family family, Classification classification,
                const PortResult* tcp, const PortResult* udp, uint16_t tcpPort);

/**
 * Fold behaviour-discovery results into a decision.
 *
 * Never changes the mode: behaviour discovery is all client-initiated, so a
 * good result says nothing about whether strangers can reach the client.
 */
void applyNat(Decision& decision, const NatResult& nat);

/** One sentence covering every family that was tested. */
std::string combine(const std::vector<Decision>& decisions);

}

#endif // HAVE_DROP_TYPES_H
