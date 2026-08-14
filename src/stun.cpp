/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/stun.h>

#include "hmac.h"

#include <arpa/inet.h>
#include <string.h>

#include <zlib.h>  /* crc32, for FINGERPRINT; Samurai already links zlib */

namespace Drop {
namespace Stun {

namespace {

constexpr uint8_t FAMILY_IPV4 = 0x01;
constexpr uint8_t FAMILY_IPV6 = 0x02;

uint16_t readU16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t readU32(const uint8_t* p)
{
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
	     | (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

void writeU16(std::vector<uint8_t>& out, uint16_t v)
{
	out.push_back(static_cast<uint8_t>(v >> 8));
	out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void writeU32(std::vector<uint8_t>& out, uint32_t v)
{
	out.push_back(static_cast<uint8_t>(v >> 24));
	out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
	out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>(v & 0xFF));
}

size_t padding(size_t length) { return (4 - (length % 4)) % 4; }

/** Attributes below 0x8000 that this implementation understands. */
bool knownRequired(uint16_t type)
{
	switch (static_cast<Attr>(type))
	{
		case Attr::MappedAddress:
		case Attr::Username:
		case Attr::MessageIntegrity:
		case Attr::ErrorCode:
		case Attr::UnknownAttributes:
		case Attr::Realm:
		case Attr::Nonce:
		case Attr::MessageIntegritySha256:
		case Attr::XorMappedAddress:
		case Attr::ChangeRequest:
		case Attr::Padding:
		case Attr::ResponsePort:
			return true;
		default:
			return false;
	}
}

} // namespace

std::string Endpoint::toString() const
{
	if (v6)
		return "[" + address + "]:" + std::to_string(port);
	return address + ":" + std::to_string(port);
}

std::optional<Endpoint> parseEndpoint(std::string_view address, uint16_t port)
{
	const std::string text(address);
	Endpoint out;
	out.port = port;

	uint8_t buf[16];
	if (inet_pton(AF_INET, text.c_str(), buf) == 1)
	{
		out.address = text;
		out.v6 = false;
		return out;
	}
	if (inet_pton(AF_INET6, text.c_str(), buf) == 1)
	{
		out.address = text;
		out.v6 = true;
		return out;
	}
	return std::nullopt;
}

bool Message::looksLikeStun(std::span<const uint8_t> datagram)
{
	if (datagram.size() < HEADER_SIZE)
		return false;
	if ((datagram[0] & 0xC0) != 0)
		return false;
	return readU32(datagram.data() + 4) == MAGIC_COOKIE;
}

bool Message::decode(std::span<const uint8_t> datagram, Message& out)
{
	if (!looksLikeStun(datagram))
		return false;

	const size_t length = readU16(datagram.data() + 2);
	if (length % 4 != 0)
		return false;
	if (HEADER_SIZE + length > datagram.size())
		return false;

	out = Message();
	out.type = readU16(datagram.data());
	memcpy(out.txid.data(), datagram.data() + 8, out.txid.size());

	/* Bytes past the declared length are not part of the message. */
	out.raw.assign(datagram.begin(), datagram.begin() + HEADER_SIZE + length);

	size_t offset = 0;
	const uint8_t* body = out.raw.data() + HEADER_SIZE;

	while (offset < length)
	{
		if (offset + 4 > length)
			return false;

		Attribute attr;
		attr.type = static_cast<Attr>(readU16(body + offset));
		const size_t valueLength = readU16(body + offset + 2);
		offset += 4;

		if (offset + valueLength > length)
			return false;

		attr.value.assign(body + offset, body + offset + valueLength);
		offset += valueLength;

		/* Padding to a four-byte boundary, which may be absent at the very end. */
		const size_t pad = padding(valueLength);
		offset = (offset + pad > length) ? length : offset + pad;

		out.attributes.push_back(std::move(attr));
	}

	return true;
}

const std::vector<uint8_t>* Message::get(Attr type) const
{
	for (const Attribute& attr : attributes)
	{
		if (attr.type == type)
			return &attr.value;
	}
	return nullptr;
}

void Message::add(Attr type, std::span<const uint8_t> value)
{
	Attribute attr;
	attr.type = type;
	attr.value.assign(value.begin(), value.end());
	attributes.push_back(std::move(attr));
}

void Message::addUint32(Attr type, uint32_t value)
{
	std::vector<uint8_t> buf;
	writeU32(buf, value);
	add(type, buf);
}

void Message::addString(Attr type, std::string_view text)
{
	add(type, std::span<const uint8_t>(
		reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

void Message::addAddress(Attr type, const Endpoint& endpoint, bool xorObscured)
{
	uint8_t raw[16];
	size_t size = 0;

	if (endpoint.v6)
	{
		if (inet_pton(AF_INET6, endpoint.address.c_str(), raw) != 1) return;
		size = 16;
	}
	else
	{
		if (inet_pton(AF_INET, endpoint.address.c_str(), raw) != 1) return;
		size = 4;
	}

	std::vector<uint8_t> value;
	value.push_back(0);
	value.push_back(endpoint.v6 ? FAMILY_IPV6 : FAMILY_IPV4);

	uint16_t port = endpoint.port;
	if (xorObscured)
		port ^= static_cast<uint16_t>(MAGIC_COOKIE >> 16);
	writeU16(value, port);

	if (xorObscured)
	{
		uint8_t mask[16];
		mask[0] = static_cast<uint8_t>(MAGIC_COOKIE >> 24);
		mask[1] = static_cast<uint8_t>((MAGIC_COOKIE >> 16) & 0xFF);
		mask[2] = static_cast<uint8_t>((MAGIC_COOKIE >> 8) & 0xFF);
		mask[3] = static_cast<uint8_t>(MAGIC_COOKIE & 0xFF);
		memcpy(mask + 4, txid.data(), txid.size());
		for (size_t i = 0; i < size; i++)
			raw[i] ^= mask[i];
	}

	value.insert(value.end(), raw, raw + size);
	add(type, value);
}

std::optional<Endpoint> Message::getAddress(Attr type, bool xorObscured) const
{
	const std::vector<uint8_t>* value = get(type);
	if (!value || value->size() < 4)
		return std::nullopt;

	const uint8_t family = (*value)[1];
	size_t size = 0;
	if (family == FAMILY_IPV4)      size = 4;
	else if (family == FAMILY_IPV6) size = 16;
	else return std::nullopt;

	if (value->size() < 4 + size)
		return std::nullopt;

	uint16_t port = readU16(value->data() + 2);
	if (xorObscured)
		port ^= static_cast<uint16_t>(MAGIC_COOKIE >> 16);

	uint8_t raw[16];
	memcpy(raw, value->data() + 4, size);

	if (xorObscured)
	{
		uint8_t mask[16];
		mask[0] = static_cast<uint8_t>(MAGIC_COOKIE >> 24);
		mask[1] = static_cast<uint8_t>((MAGIC_COOKIE >> 16) & 0xFF);
		mask[2] = static_cast<uint8_t>((MAGIC_COOKIE >> 8) & 0xFF);
		mask[3] = static_cast<uint8_t>(MAGIC_COOKIE & 0xFF);
		memcpy(mask + 4, txid.data(), txid.size());
		for (size_t i = 0; i < size; i++)
			raw[i] ^= mask[i];
	}

	char text[INET6_ADDRSTRLEN] = { 0 };
	if (!inet_ntop(size == 4 ? AF_INET : AF_INET6, raw, text, sizeof(text)))
		return std::nullopt;

	Endpoint out;
	out.address = text;
	out.port = port;
	out.v6 = (size == 16);
	return out;
}

std::optional<std::string> Message::getUsername() const
{
	const std::vector<uint8_t>* value = get(Attr::Username);
	if (!value)
		return std::nullopt;
	return std::string(value->begin(), value->end());
}

std::optional<uint32_t> Message::getChangeRequest() const
{
	const std::vector<uint8_t>* value = get(Attr::ChangeRequest);
	if (!value || value->size() != 4)
		return std::nullopt;
	return readU32(value->data());
}

bool Message::getErrorCode(int& code, std::string& reason) const
{
	const std::vector<uint8_t>* value = get(Attr::ErrorCode);
	if (!value || value->size() < 4)
		return false;
	code = static_cast<int>((*value)[2]) * 100 + static_cast<int>((*value)[3]);
	reason.assign(value->begin() + 4, value->end());
	return true;
}

std::vector<uint16_t> Message::unknownRequired() const
{
	std::vector<uint16_t> out;
	for (const Attribute& attr : attributes)
	{
		const uint16_t type = static_cast<uint16_t>(attr.type);
		if (type < 0x8000 && !knownRequired(type))
			out.push_back(type);
	}
	return out;
}

static void appendAttribute(std::vector<uint8_t>& out, const Attribute& attr)
{
	writeU16(out, static_cast<uint16_t>(attr.type));
	writeU16(out, static_cast<uint16_t>(attr.value.size()));
	out.insert(out.end(), attr.value.begin(), attr.value.end());
	for (size_t i = 0, n = padding(attr.value.size()); i < n; i++)
		out.push_back(0);
}

std::vector<uint8_t> Message::encode() const
{
	std::vector<uint8_t> body;
	for (const Attribute& attr : attributes)
		appendAttribute(body, attr);

	std::vector<uint8_t> out;
	out.reserve(HEADER_SIZE + body.size());
	writeU16(out, type);
	writeU16(out, static_cast<uint16_t>(body.size()));
	writeU32(out, MAGIC_COOKIE);
	out.insert(out.end(), txid.begin(), txid.end());
	out.insert(out.end(), body.begin(), body.end());
	return out;
}

std::vector<uint8_t> Message::encodeForIntegrity(size_t digestSize) const
{
	std::vector<uint8_t> body;
	for (const Attribute& attr : attributes)
		appendAttribute(body, attr);

	std::vector<uint8_t> out;
	writeU16(out, type);
	/* As though the attribute about to be appended were already present. */
	writeU16(out, static_cast<uint16_t>(body.size() + 4 + digestSize));
	writeU32(out, MAGIC_COOKIE);
	out.insert(out.end(), txid.begin(), txid.end());
	out.insert(out.end(), body.begin(), body.end());
	return out;
}

void Message::addMessageIntegrity(std::span<const uint8_t> key)
{
	const std::vector<uint8_t> partial = encodeForIntegrity(20);
	add(Attr::MessageIntegrity, Crypto::hmacSha1(key, partial));
}

void Message::addMessageIntegritySha256(std::span<const uint8_t> key)
{
	const std::vector<uint8_t> partial = encodeForIntegrity(32);
	add(Attr::MessageIntegritySha256, Crypto::hmacSha256(key, partial));
}

bool Message::attributeOffset(Attr want, size_t& out) const
{
	if (raw.size() < HEADER_SIZE)
		return false;
	const size_t length = raw.size() - HEADER_SIZE;
	const uint8_t* body = raw.data() + HEADER_SIZE;

	size_t offset = 0;
	while (offset + 4 <= length)
	{
		const Attr type = static_cast<Attr>(readU16(body + offset));
		const size_t valueLength = readU16(body + offset + 2);
		if (type == want)
		{
			out = HEADER_SIZE + offset;
			return true;
		}
		offset += 4 + valueLength + padding(valueLength);
	}
	return false;
}

bool Message::checkMessageIntegrity(std::span<const uint8_t> key) const
{
	if (raw.empty())
		return false;

	bool checked = false;

	struct Candidate { Attr attr; size_t size; bool sha256; };
	const Candidate candidates[] = {
		{ Attr::MessageIntegritySha256, 32, true },
		{ Attr::MessageIntegrity,       20, false },
	};

	for (const Candidate& candidate : candidates)
	{
		const std::vector<uint8_t>* got = get(candidate.attr);
		if (!got)
			continue;
		if (got->size() != candidate.size)
			return false;

		size_t offset = 0;
		if (!attributeOffset(candidate.attr, offset))
			return false;

		/* The original bytes up to the attribute, with the length rewritten to
		   end just past it. */
		std::vector<uint8_t> partial(raw.begin(), raw.begin() + offset);
		const uint16_t rewritten =
			static_cast<uint16_t>(offset - HEADER_SIZE + 4 + candidate.size);
		partial[2] = static_cast<uint8_t>(rewritten >> 8);
		partial[3] = static_cast<uint8_t>(rewritten & 0xFF);

		const std::vector<uint8_t> want = candidate.sha256
			? Crypto::hmacSha256(key, partial)
			: Crypto::hmacSha1(key, partial);

		if (!Crypto::equals(want, *got))
			return false;
		checked = true;
	}

	return checked;
}

void Message::addFingerprint()
{
	const std::vector<uint8_t> partial = encodeForIntegrity(4);
	const uint32_t value =
		static_cast<uint32_t>(crc32(0L, partial.data(),
		                            static_cast<unsigned>(partial.size()))) ^ 0x5354554Eu;
	addUint32(Attr::Fingerprint, value);
}

bool Message::checkFingerprint() const
{
	const std::vector<uint8_t>* got = get(Attr::Fingerprint);
	if (!got)
		return true;  /* optional */
	if (got->size() != 4 || raw.empty())
		return false;

	size_t offset = 0;
	if (!attributeOffset(Attr::Fingerprint, offset))
		return false;

	std::vector<uint8_t> partial(raw.begin(), raw.begin() + offset);
	const uint16_t rewritten = static_cast<uint16_t>(offset - HEADER_SIZE + 8);
	partial[2] = static_cast<uint8_t>(rewritten >> 8);
	partial[3] = static_cast<uint8_t>(rewritten & 0xFF);

	const uint32_t want =
		static_cast<uint32_t>(crc32(0L, partial.data(),
		                            static_cast<unsigned>(partial.size()))) ^ 0x5354554Eu;
	return readU32(got->data()) == want;
}

Message Message::request(const TxId& txid)
{
	Message m;
	m.type = BINDING_REQUEST;
	m.txid = txid;
	return m;
}

Message Message::response(const Message& toRequest)
{
	Message m;
	m.type = BINDING_RESPONSE;
	m.txid = toRequest.txid;
	return m;
}

Message Message::error(const Message& toRequest, int code, std::string_view reason)
{
	Message m;
	m.type = BINDING_ERROR;
	m.txid = toRequest.txid;

	std::vector<uint8_t> value(4, 0);
	value[2] = static_cast<uint8_t>(code / 100);
	value[3] = static_cast<uint8_t>(code % 100);
	value.insert(value.end(), reason.begin(), reason.end());
	m.add(Attr::ErrorCode, value);
	return m;
}

bool newTxId(TxId& out)
{
	return Crypto::randomBytes(out);
}

}
}
