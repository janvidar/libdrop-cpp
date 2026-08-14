/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#include <drop/stun.h>

#include <span>
#include <string>
#include <vector>
#include <stdint.h>
#include <string.h>

/*
 * The STUN codec decodes datagrams from anywhere on the internet, so as much
 * of this is about what it refuses as about what it parses. The prefix and
 * mutation sweeps at the end are what cover reading off the end of a truncated
 * or hostile message.
 *
 * Deterministic; nothing here touches the network.
 */

namespace {

using namespace Drop::Stun;

std::span<const uint8_t> view(const std::vector<uint8_t>& v)
{
	return std::span<const uint8_t>(v.data(), v.size());
}

TxId fixedTxId(uint8_t seed = 1)
{
	TxId id{};
	for (size_t i = 0; i < id.size(); i++)
		id[i] = static_cast<uint8_t>(seed + i);
	return id;
}

std::span<const uint8_t> key(const char* text)
{
	return std::span<const uint8_t>(
		reinterpret_cast<const uint8_t*>(text), strlen(text));
}

/** A well-formed request, as a starting point for mutation. */
std::vector<uint8_t> validRequest()
{
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "session-id");
	m.addFingerprint();
	return m.encode();
}

} // namespace

EXO_TEST(stun_round_trip, {
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");
	m.addUint32(Attr::ChangeRequest, CHANGE_IP | CHANGE_PORT);

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	const std::optional<std::string> user = got.getUsername();
	const std::optional<uint32_t> change = got.getChangeRequest();

	return got.type == BINDING_REQUEST
	    && got.txid == fixedTxId()
	    && user && *user == "user"
	    && change && (*change & CHANGE_IP) && (*change & CHANGE_PORT);
});

EXO_TEST(stun_xor_mapped_address_round_trip, {
	const char* addresses[] = {
		"81.191.239.108", "0.0.0.0", "255.255.255.255",
		"2001:db8::1", "2a03:b0c0:3:f0:0:2:ce4c:7000",
	};

	for (const char* text : addresses)
	{
		const std::optional<Endpoint> want = parseEndpoint(text, 51343);
		if (!want) return false;

		Message m = Message::response(Message::request(fixedTxId()));
		m.addAddress(Attr::XorMappedAddress, *want, true);

		Message got;
		if (!Message::decode(view(m.encode()), got)) return false;

		const std::optional<Endpoint> back =
			got.getAddress(Attr::XorMappedAddress, true);
		if (!back || *back != *want) return false;
	}
	return true;
});

EXO_TEST(stun_xor_actually_obscures_and_plain_does_not, {
	/*
	 * The obfuscation exists because middleboxes rewrite addresses they find
	 * in payloads. RFC 5780 defines OTHER-ADDRESS without it, and obscuring
	 * that one would make every behaviour-discovery client read the wrong
	 * alternate address.
	 */
	const std::optional<Endpoint> endpoint = parseEndpoint("203.0.113.7", 3478);
	if (!endpoint) return false;

	Message obscured = Message::request(fixedTxId());
	obscured.addAddress(Attr::XorMappedAddress, *endpoint, true);
	const std::vector<uint8_t> a = obscured.encode();

	Message plain = Message::request(fixedTxId());
	plain.addAddress(Attr::OtherAddress, *endpoint, false);
	const std::vector<uint8_t> b = plain.encode();

	const uint8_t raw[] = { 203, 0, 113, 7 };
	auto contains = [&](const std::vector<uint8_t>& hay) {
		for (size_t i = 0; i + 4 <= hay.size(); i++)
			if (memcmp(hay.data() + i, raw, 4) == 0) return true;
		return false;
	};

	return !contains(a) && contains(b);
});

EXO_TEST(stun_demultiplexes_against_adc, {
	/*
	 * The rule that lets a DC client share one socket between STUN and its own
	 * UDP search results: STUN has its top two bits zero and a fixed magic
	 * cookie, while every ADC message begins with an ASCII context letter.
	 */
	if (!Message::looksLikeStun(view(validRequest()))) return false;

	const char* adc[] = {
		"URES IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KCII SI1234 SL3\n",
		"BINF AAAA NIfoo\n",
		"CSUP ADBAS0 ADTIGR\n",
	};
	for (const char* text : adc)
	{
		const std::span<const uint8_t> datagram(
			reinterpret_cast<const uint8_t*>(text), strlen(text));
		if (Message::looksLikeStun(datagram)) return false;
		/* And the property the demux rests on. */
		if ((static_cast<uint8_t>(text[0]) & 0xC0) == 0) return false;
	}

	/* Too short, and right length but wrong cookie. */
	const std::vector<uint8_t> shortOne(19, 0);
	const std::vector<uint8_t> noCookie(32, 0);
	return !Message::looksLikeStun(view(shortOne))
	    && !Message::looksLikeStun(view(noCookie));
});

EXO_TEST(stun_message_integrity, {
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");
	m.addMessageIntegrity(key("secret"));

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	return got.checkMessageIntegrity(key("secret"))
	    && !got.checkMessageIntegrity(key("wrong"));
});

EXO_TEST(stun_message_integrity_sha256_and_sha1_together, {
	Message m = Message::request(fixedTxId());
	m.addMessageIntegritySha256(key("secret"));
	m.addMessageIntegrity(key("secret"));
	m.addFingerprint();

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	return got.has(Attr::MessageIntegritySha256)
	    && got.has(Attr::MessageIntegrity)
	    && got.checkMessageIntegrity(key("secret"))
	    && !got.checkMessageIntegrity(key("wrong"))
	    && got.checkFingerprint();
});

EXO_TEST(stun_unauthenticated_message_never_verifies, {
	/*
	 * A caller asking to verify integrity must never be told "valid" for a
	 * message that carried none. This is the difference between an
	 * authenticated probe and an anonymous datagram.
	 */
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	return !got.checkMessageIntegrity(key("anything"))
	    && !got.checkMessageIntegrity(key(""));
});

EXO_TEST(stun_integrity_detects_tampering, {
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");
	const std::optional<Endpoint> endpoint = parseEndpoint("203.0.113.7", 1);
	m.addAddress(Attr::XorMappedAddress, *endpoint, true);
	m.addMessageIntegrity(key("secret"));

	const std::vector<uint8_t> original = m.encode();

	/* Flip a bit at every offset before the digest and confirm none passes. */
	for (size_t i = 0; i < original.size(); i++)
	{
		std::vector<uint8_t> tampered = original;
		tampered[i] ^= 0xFF;

		Message got;
		if (!Message::decode(view(tampered), got))
			continue;  /* a mangled length is caught earlier, which is fine */
		if (got.checkMessageIntegrity(key("secret")))
		{
			/* The only bytes whose change may legitimately go unnoticed are
			   inside the digest itself, and those must fail the comparison. */
			return false;
		}
	}
	return true;
});

EXO_TEST(stun_a_truncated_digest_does_not_verify, {
	Message m = Message::request(fixedTxId());
	const uint8_t stub[] = { 1, 2, 3 };
	m.add(Attr::MessageIntegrity, std::span<const uint8_t>(stub, sizeof(stub)));

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;
	return !got.checkMessageIntegrity(key("secret"));
});

EXO_TEST(stun_fingerprint, {
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");
	m.addFingerprint();

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;
	if (!got.checkFingerprint()) return false;

	/* Absent is fine; the attribute is optional. */
	Message plain;
	Message bare = Message::request(fixedTxId());
	if (!Message::decode(view(bare.encode()), plain)) return false;
	return plain.checkFingerprint();
});

EXO_TEST(stun_fingerprint_detects_tampering, {
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "user");
	m.addFingerprint();

	std::vector<uint8_t> wire = m.encode();
	wire[25] ^= 0xFF;

	Message got;
	if (!Message::decode(view(wire), got)) return false;
	return !got.checkFingerprint();
});

EXO_TEST(stun_error_response, {
	const Message request = Message::request(fixedTxId());
	Message m = Message::error(request, CODE_UNAUTHORIZED, "Unauthorized");

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	int code = 0;
	std::string reason;
	return got.type == BINDING_ERROR
	    && got.txid == request.txid   /* an error must echo the transaction */
	    && got.getErrorCode(code, reason)
	    && code == 401
	    && reason == "Unauthorized";
});

EXO_TEST(stun_unknown_comprehension_required_attributes, {
	Message m = Message::request(fixedTxId());
	const uint8_t value[] = { 1, 2, 3, 4 };
	m.add(static_cast<Attr>(0x7ABC), std::span<const uint8_t>(value, 4));
	m.add(static_cast<Attr>(0x8ABC), std::span<const uint8_t>(value, 4));
	m.addString(Attr::Username, "known");

	Message got;
	if (!Message::decode(view(m.encode()), got)) return false;

	const std::vector<uint16_t> unknown = got.unknownRequired();
	return unknown.size() == 1 && unknown[0] == 0x7ABC;
});

EXO_TEST(stun_odd_length_attributes_are_padded, {
	/* Padding is not part of the value, and the attribute after an odd-length
	   one must still parse. */
	for (const char* text : { "a", "ab", "abc", "abcd", "abcde" })
	{
		Message m = Message::request(fixedTxId());
		m.addString(Attr::Username, text);
		m.addString(Attr::Software, "after");

		Message got;
		if (!Message::decode(view(m.encode()), got)) return false;

		const std::optional<std::string> user = got.getUsername();
		const std::vector<uint8_t>* after = got.get(Attr::Software);
		if (!user || *user != text) return false;
		if (!after || std::string(after->begin(), after->end()) != "after")
			return false;
	}
	return true;
});

EXO_TEST(stun_refuses_malformed_messages, {
	std::vector<std::vector<uint8_t>> cases;

	cases.push_back({});                       /* empty */
	cases.push_back(std::vector<uint8_t>(19)); /* shorter than the header */

	{   /* top two bits set */
		std::vector<uint8_t> v = validRequest();
		v[0] |= 0xC0;
		cases.push_back(v);
	}
	{   /* wrong magic cookie */
		std::vector<uint8_t> v = validRequest();
		v[4] ^= 0xFF;
		cases.push_back(v);
	}
	{   /* declared length is not a multiple of four */
		std::vector<uint8_t> v = validRequest();
		v[3] = static_cast<uint8_t>(v[3] + 1);
		cases.push_back(v);
	}
	{   /* declared length runs past the buffer */
		std::vector<uint8_t> v = validRequest();
		v[2] = 0xFF;
		v[3] = 0xF0;
		cases.push_back(v);
	}
	{   /* an attribute claiming far more than exists */
		std::vector<uint8_t> v(28, 0);
		v[0] = 0x00; v[1] = 0x01;         /* binding request */
		v[2] = 0x00; v[3] = 0x08;         /* length 8 */
		v[4] = 0x21; v[5] = 0x12; v[6] = 0xA4; v[7] = 0x42;
		v[20] = 0x00; v[21] = 0x06;       /* USERNAME */
		v[22] = 0xFF; v[23] = 0x00;       /* absurd length */
		cases.push_back(v);
	}

	for (const std::vector<uint8_t>& v : cases)
	{
		Message got;
		if (Message::decode(view(v), got))
			return false;
	}
	return true;
});

EXO_TEST(stun_every_prefix_of_a_valid_message_is_safe, {
	/*
	 * Reading off the end of a truncated datagram is the failure a parser of
	 * network input must not have, so every prefix is fed in and asserted
	 * merely not to crash or to be mistaken for the whole.
	 */
	Message m = Message::request(fixedTxId());
	m.addString(Attr::Username, "session-id");
	const std::optional<Endpoint> endpoint = parseEndpoint("2001:db8::1", 3478);
	m.addAddress(Attr::XorMappedAddress, *endpoint, true);
	m.addMessageIntegrity(key("secret"));
	m.addFingerprint();

	const std::vector<uint8_t> whole = m.encode();

	for (size_t n = 0; n < whole.size(); n++)
	{
		const std::span<const uint8_t> prefix(whole.data(), n);
		Message got;
		if (Message::decode(prefix, got))
		{
			/*
			 * A prefix may decode when the declared length happens to fit what
			 * is present, but it must never verify: the digest covers bytes
			 * that are not there.
			 */
			if (got.checkMessageIntegrity(key("secret")))
				return false;
		}
	}
	return true;
});

EXO_TEST(stun_single_byte_mutations_never_crash, {
	/* Every byte of a valid message, set to every interesting value. */
	const std::vector<uint8_t> original = validRequest();
	const uint8_t values[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };

	for (size_t i = 0; i < original.size(); i++)
	{
		for (uint8_t v : values)
		{
			std::vector<uint8_t> mutated = original;
			mutated[i] = v;

			Message got;
			if (!Message::decode(view(mutated), got))
				continue;

			/* Everything a caller might reach for must be safe on anything
			   that decoded. */
			got.getAddress(Attr::XorMappedAddress, true);
			got.getAddress(Attr::OtherAddress, false);
			got.getUsername();
			got.getChangeRequest();
			got.unknownRequired();
			got.checkFingerprint();
			got.checkMessageIntegrity(key("secret"));
			int code = 0;
			std::string reason;
			got.getErrorCode(code, reason);
			got.encode();
		}
	}
	return true;
});

EXO_TEST(stun_transaction_ids_are_unpredictable, {
	/* A guessable transaction id would let an off-path attacker forge a
	   response, so this is a security property rather than hygiene. */
	TxId a{};
	TxId b{};
	if (!newTxId(a) || !newTxId(b)) return false;

	if (a == b) return false;

	bool allZero = true;
	for (uint8_t byte : a)
	{
		if (byte != 0) { allZero = false; break; }
	}
	return !allZero;
});

EXO_TEST(stun_parse_endpoint_rejects_nonsense, {
	return !parseEndpoint("not an address", 1).has_value()
	    && !parseEndpoint("", 1).has_value()
	    && !parseEndpoint("999.999.999.999", 1).has_value()
	    && parseEndpoint("127.0.0.1", 1).has_value()
	    && parseEndpoint("::1", 1).has_value();
});

EXO_TEST(stun_endpoint_formatting, {
	const std::optional<Endpoint> v4 = parseEndpoint("203.0.113.7", 3478);
	const std::optional<Endpoint> v6 = parseEndpoint("2001:db8::1", 3478);

	return v4 && v4->toString() == "203.0.113.7:3478"
	    && v6 && v6->toString() == "[2001:db8::1]:3478";
});
