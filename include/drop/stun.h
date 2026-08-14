/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_STUN_H
#define HAVE_DROP_STUN_H

#include <stddef.h>
#include <stdint.h>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

/**
 * The subset of STUN that DROP needs: RFC 8489 Binding messages with
 * short-term credentials, plus the RFC 5780 attributes.
 *
 * Public rather than internal because a DC client integrating DROP has to
 * demultiplex STUN from its own UDP traffic on the socket it advertises in
 * U4/U6, and needs Message::looksLikeStun() to do it.
 */
namespace Drop {
namespace Stun {

constexpr uint32_t MAGIC_COOKIE = 0x2112A442u;
constexpr size_t HEADER_SIZE = 20;

enum : uint16_t
{
	BINDING_REQUEST    = 0x0001,
	BINDING_INDICATION = 0x0011,
	BINDING_RESPONSE   = 0x0101,
	BINDING_ERROR      = 0x0111
};

/**
 * Attribute types.
 *
 * Below 0x8000 is comprehension-required: an agent that does not understand
 * one must reject the message. At or above is comprehension-optional.
 */
enum class Attr : uint16_t
{
	MappedAddress          = 0x0001,
	Username               = 0x0006,
	MessageIntegrity       = 0x0008,
	ErrorCode              = 0x0009,
	UnknownAttributes      = 0x000A,
	Realm                  = 0x0014,
	Nonce                  = 0x0015,
	MessageIntegritySha256 = 0x001C,
	XorMappedAddress       = 0x0020,
	Software               = 0x8022,
	Fingerprint            = 0x8028,

	/* RFC 5780, NAT behaviour discovery. */
	ChangeRequest  = 0x0003,
	Padding        = 0x0026,
	ResponsePort   = 0x0027,
	ResponseOrigin = 0x802b,
	OtherAddress   = 0x802c,

	/**
	 * Marks a Binding Request as a DROP unsolicited inbound probe, so a client
	 * knows to apply the DROP response rules rather than treating it as
	 * ordinary STUN. Provisional and unregistered; comprehension-optional, so
	 * a stock agent ignores it.
	 */
	DropProbe = 0xFF0D
};

/** CHANGE-REQUEST flags (RFC 5780 section 7.2). */
enum : uint32_t { CHANGE_IP = 0x04, CHANGE_PORT = 0x02 };

enum : int { CODE_BAD_REQUEST = 400, CODE_UNAUTHORIZED = 401, CODE_UNKNOWN_ATTR = 420 };

using TxId = std::array<uint8_t, 12>;

/** An address as carried in an address attribute. */
struct Endpoint
{
	std::string address;
	uint16_t port = 0;
	bool v6 = false;

	bool valid() const { return !address.empty(); }
	std::string toString() const;

	bool operator==(const Endpoint&) const = default;
};

/** Parse "1.2.3.4" or "2001:db8::1" into the wire form. */
std::optional<Endpoint> parseEndpoint(std::string_view address, uint16_t port);

/** One type-length-value. */
struct Attribute
{
	Attr type = Attr::MappedAddress;
	std::vector<uint8_t> value;
};

/**
 * A STUN message.
 *
 * Decoding is bounds-checked throughout: this runs on unauthenticated
 * datagrams from anywhere.
 */
class Message
{
	public:
		uint16_t type = BINDING_REQUEST;
		TxId txid{};
		std::vector<Attribute> attributes;

		/**
		 * Whether a datagram plausibly begins a STUN message.
		 *
		 * The demultiplexing test for a socket carrying both STUN and
		 * something else. Every STUN message has its top two bits zero and the
		 * fixed magic cookie at offset 4, while ADC UDP messages begin with an
		 * ASCII letter - 'U' for URES, whose top bits are 01 - so the two
		 * cannot be confused.
		 */
		static bool looksLikeStun(std::span<const uint8_t> datagram);

		/** @return false for anything malformed, without reading past the end. */
		static bool decode(std::span<const uint8_t> datagram, Message& out);

		std::vector<uint8_t> encode() const;

		const std::vector<uint8_t>* get(Attr type) const;
		bool has(Attr type) const { return get(type) != nullptr; }

		void add(Attr type, std::span<const uint8_t> value);
		void addUint32(Attr type, uint32_t value);
		void addString(Attr type, std::string_view text);
		void addAddress(Attr type, const Endpoint& endpoint, bool xorObscured);

		std::optional<Endpoint> getAddress(Attr type, bool xorObscured) const;
		std::optional<std::string> getUsername() const;
		std::optional<uint32_t> getChangeRequest() const;
		bool getErrorCode(int& code, std::string& reason) const;

		/** Comprehension-required attributes this implementation does not know. */
		std::vector<uint16_t> unknownRequired() const;

		/*
		 * MESSAGE-INTEGRITY covers the message up to but not including the
		 * attribute, with the header length rewritten as though it were
		 * already there (RFC 8489 section 14.5). Both are added, SHA-256 first,
		 * because RFC 8489 keeps SHA-1 as the baseline and most deployed
		 * libraries implement only that.
		 */
		void addMessageIntegrity(std::span<const uint8_t> key);
		void addMessageIntegritySha256(std::span<const uint8_t> key);
		void addFingerprint();

		/**
		 * Verify integrity against a key.
		 *
		 * False when no integrity attribute is present at all: a caller asking
		 * to verify must never be told "valid" for an unauthenticated message.
		 */
		bool checkMessageIntegrity(std::span<const uint8_t> key) const;

		/** True when absent, since FINGERPRINT is optional. */
		bool checkFingerprint() const;

		static Message request(const TxId& txid);
		static Message response(const Message& toRequest);
		static Message error(const Message& toRequest, int code, std::string_view reason);

	private:
		/** The bytes decoded from, kept because integrity covers the original. */
		std::vector<uint8_t> raw;

		std::vector<uint8_t> encodeForIntegrity(size_t digestSize) const;
		bool attributeOffset(Attr type, size_t& out) const;
};

/** A fresh, unpredictable transaction id. */
bool newTxId(TxId& out);

}
}

#endif // HAVE_DROP_STUN_H
