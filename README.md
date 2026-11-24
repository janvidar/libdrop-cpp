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

    Samurai::EventLoop loop;

    Drop::CheckOptions options;
    options.families = { Drop::Family::IPv4, Drop::Family::IPv6 };
    options.useUpnp = true;

    const Drop::Report report = Drop::check(loop, "https://drop.quickdc.org", options);

    for (const Drop::FamilyReport& fr : report.families) {
        printf("%s: %s\n", toString(fr.family), toString(fr.decision.mode));
        printf("  %s\n", fr.decision.reason.c_str());
    }

The blocking `check()` drives the loop it is given itself and must not be called
from inside an event handler. A client that runs its own event loop uses
`Drop::Client` and the responders directly; `src/check.cpp` is the worked
example of doing so.

## Two things worth knowing before integrating

**Run the responders on the sockets you actually advertise.** A test of any
other socket measures a different port than the one in your `U4`/`U6`. Both
responders expose their protocol as free functions — `handleChallenge()` and
`handleStunProbe()` — so a client folds them into listeners it already has
rather than opening a second pair. See
[`docs/adc-integration.md`](docs/adc-integration.md), which is the
one-pager for client authors.

**Pin your source address on a multi-homed host.** A host with several
addresses of one family has no single source address: the kernel picks one per
destination, preferring the longest matching prefix. A check that does not name
one can therefore measure a different address than the one the client
advertises. Set `CheckOptions::localAddress`.

## Status

All three of the questions above are answered, and verified against the live
deployment at `drop.quickdc.org` from a real NAT'd connection:

- the control plane (`/v1/server`, `/v1/whoami`, `/v1/session`, `/inbound`)
- the STUN codec, interoperating with the Go server implementation
- the TCP challenge responder and the STUN responder
- the UPnP check-map-recheck loop, which on a real router took the verdict
  from `filtered` to `open`
- `check()` and the `dropcheck` tool

RFC 5780 NAT behaviour discovery is included, and verified against the live
server over IPv6 -- the family where it offers a second address. On a host with
no NAT it correctly reports `mapping: none` and `filtering:
endpoint-independent`, matching what the Go client reports for the same host.

## Tests

    cmake --build build && ./build/test/droptest

109 tests through [exotic](https://github.com/janvidar/exotic), the framework
Samurai and uhub use. They need no network: the responder cases stand up real
sockets on the loopback interface, and everything else is pure logic or a
captured document.

The weight is on what should be *refused* rather than on the happy path — an
open reflector, a peer that is not a DROP server, a request body that could
name an address, a truncated datagram.

The RFC 5780 classification is driven by a four-endpoint STUN server on the
loopback interface. A NAT is only a thing that makes the mapped address differ
per destination, so a server that simply *reports* chosen addresses exercises
every branch of the tree without one.

Confirmed to bite by mutation rather than by passing: removing the STUN
credential check, making the CGNAT advice suggest port forwarding, reporting a
refused CHANGE-REQUEST as a restrictive NAT, and collapsing the
address-dependent branch all fail the suite.

## The protocol

`doc/drop.txt` in the DROP repository is the specification. It is still marked
DRAFT pending review by client authors, and this implementation is one of the
two that shaped it — several of its rules exist because building this and the
server turned up ways to get a confident wrong answer.
