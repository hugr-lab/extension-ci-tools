#include "crypto.hpp"

#include "mbedtls_wrapper.hpp"

#include <stdexcept>

namespace kista {
namespace crypto {

using duckdb_mbedtls::MbedTlsWrapper;

std::string Sha256(const std::string &data) {
	return MbedTlsWrapper::ComputeSha256Hash(data);
}

bool IsRSA2048(const std::string &pem) {
	return MbedTlsWrapper::IsValidRSA2048PublicKey(pem);
}

std::string Der(const std::string &pem) {
	const std::string begin = "-----BEGIN PUBLIC KEY-----", end = "-----END PUBLIC KEY-----";
	auto b = pem.find(begin), e = pem.find(end);
	if (b == std::string::npos || e == std::string::npos || e < b) {
		return "";
	}
	std::string out;
	uint32_t acc = 0;
	int bits = 0;
	for (size_t i = b + begin.size(); i < e; i++) {
		char c = pem[i];
		int v;
		if (c >= 'A' && c <= 'Z') {
			v = c - 'A';
		} else if (c >= 'a' && c <= 'z') {
			v = c - 'a' + 26;
		} else if (c >= '0' && c <= '9') {
			v = c - '0' + 52;
		} else if (c == '+') {
			v = 62;
		} else if (c == '/') {
			v = 63;
		} else if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
			continue;
		} else {
			return "";
		}
		acc = (acc << 6) | uint32_t(v);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(char((acc >> bits) & 0xFF));
		}
	}
	return out;
}

bool VerifyRS256(const std::string &pem, const std::string &signed_part, const std::string &signature) {
	if (signature.size() != 256) {
		return false; // the wrapper throws on any other length
	}
	try {
		return MbedTlsWrapper::IsValidSha256Signature(pem, signature, Sha256(signed_part));
	} catch (const std::exception &) {
		return false;
	}
}

} // namespace crypto
} // namespace kista
