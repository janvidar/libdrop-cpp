# Auto-detecting active mode in an ADC client

For a client already built on Samurai. About twenty lines of real work; the
rest of this is the handful of details that decide whether the answer is
trustworthy.

## What you are asking

ADC only works peer-to-peer when at least one side is *active* — able to accept
an inbound TCP connection. Two passive clients cannot connect to each other at
all. Clients normally guess, and a wrong guess shows the user "no search
results" or a download stuck at 0% with no explanation.

DROP replaces the guess with a measurement: a server dials your listening port
from outside and tells you whether it arrived.

## The one rule that matters

**Test the sockets you actually advertise.**

Not a fresh socket, not an ephemeral port. If you test port 40000 and advertise
`U4=1511`, you have measured something true about a port nobody will ever
connect to. Both responders are therefore free functions you call from the
listeners you already own:

```cpp
#include <drop/responder.h>
```

### In your client-to-client TCP accept path

You already demultiplex `CSUP` from a TLS `ClientHello`. Add a third case:

```cpp
// The first bytes tell you which protocol this is:
//   "CSUP"      ADC client-to-client, plaintext
//   0x16 0x03   TLS ClientHello (ADCS)
//   "DROP/1 "   a DROP challenge
std::string response;
if (Drop::TcpResponder::handleChallenge(line, response)) {
    socket->write(response.data(), response.size(), ec);
    socket->close();
    return;                 // one line each way, then done
}
```

A TLS-only port must still accept the plaintext challenge. Recognising a
seven-byte prefix before the handshake costs nothing, and requiring TLS for a
single-use nonce buys nothing.

### In your `U4`/`U6` UDP read loop

The socket that receives search results is the socket that must answer:

```cpp
std::vector<uint8_t> reply;
if (Drop::handleStunProbe(datagram, stunUser, stunPass, from, reply)) {
    socket->send(reply, from);
    return;
}
// Not for us — hand it to the ADC parser as before.
```

`stunUser` and `stunPass` come from the session below, and **must be empty
whenever no check is running**. With them empty this answers nobody, which is
the point: a client that answers unauthenticated STUN is an open reflector an
attacker can aim anywhere with a spoofed source address. Clear them when the
check finishes.

Demultiplexing is unambiguous — STUN has its top two bits zero and a fixed
magic cookie, while every ADC message starts with an ASCII context letter.

## The flow

`Drop::check()` exists and is one call, but it is **blocking** and opens its own
ephemeral sockets, so it is for tools rather than for you. Drive `Drop::Client`
from your existing `SocketMonitor` instead:

```cpp
Drop::Client::Options options;
options.localAddress = myAdvertisedAddress;   // see below

Drop::Client client(this, "https://ipv4.drop.quickdc.org",
                    Drop::Family::IPv4, options);

client.requestServerInfo();   // confirms it is a DROP server
client.requestWhoami();       // your public address — useful on its own
// ... arm nothing: your listeners are already up ...
client.openSession();         // hands you the STUN credentials
client.requestInbound(session, { myTcpPort }, { myUdpPort });
```

Then apply the shared decision table rather than writing your own:

```cpp
Drop::Decision d = Drop::decide(family, whoami.classification,
                                inbound.findTcp(myTcpPort),
                                inbound.findUdp(myUdpPort),
                                myTcpPort);

if (d.mode == Drop::Mode::Active) {
    inf.set("SU", "TCP4,UDP4,...");   // the ADC active-mode signal
    inf.set("U4", std::to_string(d.advertisePort));
}
// d.reason and d.remedies are written for the user; show them verbatim.
```

That table lives in one place on purpose. A user who moves between two clients
and gets two different explanations of the same network concludes one of them
is broken.

## Five things that will bite you

**Set `SU` and `U4` together.** The ADC specification says active mode is the
`TCP4`/`TCP6` tokens in `SU`; `U4`/`U6` carry the UDP port for search results.
Deployed hubs disagree about which they read — uhub counts `U4`/`U6` and does
not recognise `TCP4` at all — so set them consistently and never infer one from
the other.

**Do not guess your own address.** Hubs discard client-supplied `I4`/`I6` and
substitute what they observe. DROP tells you whether to advertise a *port*, not
which address to claim.

**Pin your source address if you are multi-homed.** A host with several
addresses of one family has no source address until you name one: the kernel
picks per destination. Set `Options::localAddress` to the address you intend to
advertise. On IPv6 this is not an edge case — a client listening on `[::]` with
privacy extensions will otherwise have DROP validate a temporary address it
never advertises.

**Run each family separately, against its own name.** Use
`ipv4.` and `ipv6.` prefixed hostnames. One connection has one source address,
and relying on the dual-stack name leaves the family under test to whichever
connection Happy Eyeballs won. Being active on IPv6 and passive on IPv4 is a
good position and worth telling the user about — it is most of what
carrier-grade NAT would otherwise cost them.

**Cache, and re-check on change.** Key the result on the observed address, keep
it about fifteen minutes, and invalidate on interface up/down, address change,
VPN connect or resume from suspend. Re-running on every hub connect is
unnecessary and rude to a service somebody pays for.

## If the answer is passive

Ask the gateway, then **measure again** — that second measurement is the whole
point. A router grants a mapping and reports success without knowing whether
anything upstream honours it, and a second carrier-grade NAT above it will
happily let the forward be created and then drop every packet.

```cpp
Drop::CheckOptions options;
options.useUpnp = true;        // check, map, check again
options.keepMapping = true;    // keep it when it actually helped
```

A mapping that did not help is always removed. If you build this yourself with
`Drop::Upnp::addMapping()`, note that a verdict measured *through* a mapping
you then tear down does not describe the state your user is left in — say so,
or keep the mapping.

## What DROP will not tell you

`Drop::NatDiscovery` (RFC 5780) answers "would hole punching work", which is a
**different question** from "can strangers reach me". Every request in it is
client-initiated, so a good result says nothing about unsolicited inbound
traffic — only the inbound UDP probe answers that. Use it to decide whether to
offer NAT traversal, never to decide active mode.

It also runs *after* the inbound test, never before: once you have sent to the
server's STUN endpoints, a NAT doing address-dependent filtering will admit a
datagram from them that it would have dropped from a stranger — and a stranger
is precisely who sends search results.

## Before you trust an "open"

Confirm it against a second, independent DROP server. One misconfigured or
hostile checker can otherwise talk your client into an active-mode claim that
degrades the experience of every peer that tries to connect to it. Ship a small
list of servers and let the user override it.

## Where to look

- `include/drop/client.h` — the async control plane
- `include/drop/responder.h` — `handleChallenge()` and `handleStunProbe()`
- `include/drop/types.h` — `decide()`, the table, and the wire types
- `src/check.cpp` — the whole flow written out, the worked example
- `docs/drop.txt` — the protocol, normative

The specification is still DRAFT and this implementation is one of the two that
shaped it. If something here reads as arbitrary, it is probably a rule that
exists because getting it wrong produced a confident, plausible, wrong answer.
