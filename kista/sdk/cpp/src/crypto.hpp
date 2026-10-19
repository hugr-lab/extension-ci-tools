// The SDK's cryptography: DuckDB's bundled mbedtls (MbedTlsWrapper), which every C++ extension built
// with DuckDB's CMake links statically.
#pragma once

#include <string>

namespace kista {
namespace crypto {

// Sha256 returns the 32-byte digest of data.
std::string Sha256(const std::string &data);

// IsRSA2048 reports whether pem is an RSA-2048 public key (SPKI PEM).
bool IsRSA2048(const std::string &pem);

// Der returns the DER bytes of a PEM public key, or "".
std::string Der(const std::string &pem);

// VerifyRS256 checks an RSASSA-PKCS1-v1_5 SHA-256 signature (256 bytes) over signed.
bool VerifyRS256(const std::string &pem, const std::string &signed_part, const std::string &signature);

} // namespace crypto
} // namespace kista
