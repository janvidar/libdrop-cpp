/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_HMAC_H
#define HAVE_DROP_HMAC_H

#include <stddef.h>
#include <stdint.h>
#include <span>
#include <vector>

/**
 * HMAC-SHA1 and HMAC-SHA256, which STUN short-term credentials need.
 *
 * The whole of the dependency on a crypto library lives in this file and its
 * implementation. Samurai's crypto offers Tiger and a Merkle tree but no SHA
 * family and no HMAC, so this currently calls OpenSSL - which is already linked
 * for Samurai's TLS, so it costs nothing to reach.
 *
 * When Samurai grows an HMAC of its own, hmac.cpp is the only file that
 * changes. Nothing above this include is aware of which library is underneath,
 * which is the point of it being here rather than inline at the call sites.
 */
namespace Drop {
namespace Crypto {

/** 20 bytes. */
std::vector<uint8_t> hmacSha1(std::span<const uint8_t> key,
                              std::span<const uint8_t> message);

/** 32 bytes. */
std::vector<uint8_t> hmacSha256(std::span<const uint8_t> key,
                                std::span<const uint8_t> message);

/**
 * Compare in time that does not depend on where the first difference is.
 *
 * A comparison that returns early tells an attacker how much of a guess was
 * right, which is enough to find the rest one byte at a time.
 */
bool equals(std::span<const uint8_t> a, std::span<const uint8_t> b);

/** Fill with cryptographically strong random bytes. */
bool randomBytes(std::span<uint8_t> out);

}
}

#endif // HAVE_DROP_HMAC_H
