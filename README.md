# libdrop-cpp

A C++ client for **DROP**, the Diagnostic Reachability & Obstacle Probe, built
on [Samurai](ssh://git@gitea.extatic.org:2222/janvidar/samurai.git).

It answers the three questions a peer-to-peer client cannot answer alone:

1. **What are my public addresses?** IPv4 and IPv6, each tested separately.
2. **Can anything reach me on them?** Inbound TCP, and unsolicited inbound UDP
   — which is what ADC search results actually require.
3. **Does UPnP help?** Add a port mapping and *re-run the check*, rather than
   trusting the router's own report of success.

That third point is the reason this exists in the shape it does. A router can
grant a mapping and report success while a second, carrier-grade NAT upstream
still blocks every inbound packet. Only measuring from outside settles it.

## Requirements

- C++20
- Samurai, which supplies everything: sockets, TLS, HTTP client, UPnP gateway,
  JSON, and the SHA/HMAC that STUN short-term credentials need

There is no crypto dependency of its own. zlib is linked for `crc32`, which
the STUN FINGERPRINT attribute uses, and Samurai already requires it.

Samurai is found as an installed package, or built from a source tree beside
this one:

    cmake -S . -B build -DSAMURAI_SOURCE_DIR=../samurai
    cmake --build build

## What it looks like

    #include <drop/check.h>

    Drop::CheckOptions options;
    options.families = { Drop::Family::IPv4, Drop::Family::IPv6 };
    options.useUpnp = true;

    const Drop::Report report = Drop::check("https://drop.quickdc.org", options);

    for (const Drop::FamilyReport& fr : report.families) {
        printf("%s: %s\n", toString(fr.family), toString(fr.decision.mode));
        printf("  %s\n", fr.decision.reason.c_str());
    }

The blocking `check()` drives the socket monitor itself and must not be called
from inside an event handler. A client with its own event loop uses
`Drop::Client` and the responders directly; `src/check.cpp` is the worked
example of doing so.

## Two things worth knowing before integrating

**Run the responders on the sockets you actually advertise.** `UdpResponder`
must own the very socket whose port goes in ADC's `U4`/`U6`, or the test
measures a different port than the one that matters. Both responders expose
their protocol handling as free functions so a client can fold them into
listeners it already has rather than opening a second pair — see
`TcpResponder::handleChallenge()`.

**Pin your source address on a multi-homed host.** A host with several
addresses of one family has no single source address: the kernel picks one per
destination, preferring the longest matching prefix. A check that does not name
one can therefore measure a different address than the one the client
advertises. Set `CheckOptions::localAddress`.

## Status

Working and verified against the live deployment at `drop.quickdc.org`:

- the control plane (`/v1/server`, `/v1/whoami`, `/v1/session`, `/inbound`)
- the STUN codec, interoperating with the Go server implementation
- the TCP challenge responder and the STUN responder

Not yet written: `natdisc` (RFC 5780 behaviour discovery), the UPnP
check-map-recheck loop, the `check()` orchestrator that ties them together, and
the test suite. The `dropcheck` tool is written but needs `check()`.

## The protocol

`doc/drop.txt` in the DROP repository is the specification. It is still marked
DRAFT pending review by client authors, and this implementation is one of the
two that shaped it — several of its rules exist because building this and the
server turned up ways to get a confident wrong answer.
