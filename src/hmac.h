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
 * The primitives STUN short-term credentials need.
 *
 * Thin wrappers over Samurai, which supplies all of them:
 * Samurai::Crypto::hmacSha1 and hmacSha256, Samurai::Util::constantTimeEquals
 * and Samurai::Util::secureRandom. They are wrapped rather than called
 * directly only to keep the STUN code reading in terms of byte vectors instead
 * of HashValue, and to leave one place to look if any of it moves.
 *
 * There is no dependency on a crypto library here. This used to call OpenSSL
 * because Samurai had Tiger and no SHA family; it now does.
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
 * Compare without leaking where the first difference is.
 *
 * A comparison that returns early tells an attacker how much of a guess was
 * right, which turns guessing a MAC into guessing it one byte at a time.
 */
bool equals(std::span<const uint8_t> a, std::span<const uint8_t> b);

/** Fill with cryptographically strong random bytes. */
bool randomBytes(std::span<uint8_t> out);

}
}

#endif // HAVE_DROP_HMAC_H
