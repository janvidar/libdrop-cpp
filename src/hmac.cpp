/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include "hmac.h"

/*
 * The only file that knows which crypto library is underneath. See hmac.h.
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace Drop {
namespace Crypto {

namespace {

std::vector<uint8_t> hmacWith(const EVP_MD* md, size_t size,
                              std::span<const uint8_t> key,
                              std::span<const uint8_t> message)
{
	std::vector<uint8_t> out(size, 0);
	unsigned int written = 0;

	/* An empty key is legal for HMAC and must not become a null pointer, which
	   OpenSSL treats as "reuse the previous key". */
	static const uint8_t empty = 0;
	const uint8_t* keyData = key.empty() ? &empty : key.data();

	const unsigned char* result = HMAC(md, keyData, static_cast<int>(key.size()),
	                                   message.data(), message.size(),
	                                   out.data(), &written);
	if (!result || written != size)
		return std::vector<uint8_t>();

	return out;
}

} // namespace

std::vector<uint8_t> hmacSha1(std::span<const uint8_t> key,
                              std::span<const uint8_t> message)
{
	return hmacWith(EVP_sha1(), 20, key, message);
}

std::vector<uint8_t> hmacSha256(std::span<const uint8_t> key,
                                std::span<const uint8_t> message)
{
	return hmacWith(EVP_sha256(), 32, key, message);
}

bool equals(std::span<const uint8_t> a, std::span<const uint8_t> b)
{
	/* The lengths are public - they are fixed by the algorithm - so comparing
	   them early leaks nothing. The contents are not. */
	if (a.size() != b.size())
		return false;
	if (a.empty())
		return true;
	return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool randomBytes(std::span<uint8_t> out)
{
	if (out.empty())
		return true;
	/* RAND_bytes fails rather than returning weak output when the pool cannot
	   be seeded, and a transaction id that is not unpredictable would let an
	   off-path attacker forge a response. */
	return RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

}
}
