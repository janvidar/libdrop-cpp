/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include "hmac.h"

#include <samurai/crypto/hmac.h>
#include <samurai/util/random.h>

namespace Drop {
namespace Crypto {

namespace {

std::vector<uint8_t> toVector(const Samurai::Crypto::Digest::HashValue& value)
{
	const std::span<const uint8_t> bytes = value.bytes();
	return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

} // namespace

std::vector<uint8_t> hmacSha1(std::span<const uint8_t> key,
                              std::span<const uint8_t> message)
{
	return toVector(Samurai::Crypto::hmacSha1(key, message));
}

std::vector<uint8_t> hmacSha256(std::span<const uint8_t> key,
                                std::span<const uint8_t> message)
{
	return toVector(Samurai::Crypto::hmacSha256(key, message));
}

bool equals(std::span<const uint8_t> a, std::span<const uint8_t> b)
{
	return Samurai::Util::constantTimeEquals(a, b);
}

bool randomBytes(std::span<uint8_t> out)
{
	return Samurai::Util::secureRandom(out);
}

}
}
