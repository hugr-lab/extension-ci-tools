// kista SDK (spec 0012): a licence, its verifier and its status. This part uses no DuckDB type: it is
// the C++ twin of internal/license, checked against the same vectors (testdata/vectors.json).
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace kista {

// Status is what a licence means for an extension at a version and a time (spec 0012: the first row
// that applies). Missing is the SDK's own: no licence was found. (A member function named Status
// returns kista::Status, qualified.)
enum class Status { Valid, Grace, Expired, NotYetValid, NotCovered, Invalid, Missing };

// StatusName is the status as the spec, the usage reports and the vectors name it.
const char *StatusName(Status s);

// LimitValue is one of a licence's limits: a bool, an integer or a string.
struct LimitValue {
	enum class Kind { Bool, Int, String } kind = Kind::Bool;
	bool b = false;
	int64_t i = 0;
	std::string s;
};

// Claims are a licence's contents, named as kista's API names them. Times are seconds since the
// epoch; Grace is in seconds, the default (7 days) filled in.
struct Claims {
	std::string key;       // the header's kid
	std::string issuer;    // iss
	std::string id;        // jti
	std::string holder_id; // sub
	std::string holder;
	std::string extension; // ext
	bool has_versions = false;
	std::string versions_min, versions_below;
	std::string plan;
	std::vector<std::pair<std::string, LimitValue>> limits; // in the licence's order
	int64_t issued_at = 0;
	int64_t expires_at = 0;
	int64_t grace = 0;

	int64_t GraceUntil() const {
		return expires_at + grace;
	}
	// Limit returns a limit by name, or nullptr.
	const LimitValue *Limit(const std::string &name) const;
};

// Keys are the licence keys a verifier trusts: SPKI PEM, RSA-2048, by fingerprint
// ("sha256:<hex of the DER's SHA-256>", the form of a header's kid).
class Keys {
public:
	// Add adds a PEM public key; false when it is not an RSA-2048 public key with e = 65537.
	bool Add(const std::string &pem);
	// Find returns the PEM for a kid, or nullptr.
	const std::string *Find(const std::string &kid) const;
	size_t Size() const {
		return by_kid.size();
	}
	// Trusted are the keys this build of the SDK trusts: compiled in, never added at run time
	// (src/keys.cpp; the test key only in the kista_sdk_testkey library). An extension verifies
	// with these; other Keys are for tests.
	static const Keys &Trusted();

private:
	std::map<std::string, std::string> by_kid;
};

// Fingerprint returns a PEM public key's fingerprint, or "" when it is not one.
std::string Fingerprint(const std::string &pem);

// TrustsTestKey reports whether this build trusts the vectors' test-only key (kista_sdk_testkey):
// an extension's release build can assert that it does not.
bool TrustsTestKey();

// Result is a verification: the status, the rule broken (spec 0012's stable codes, as
// internal/license names them) and a message for an invalid licence, the claims otherwise.
struct Result {
	Status status = Status::Invalid;
	std::string rule;
	std::string message;
	bool has_claims = false;
	Claims claims;
};

// MaxSize bounds a licence in its compact form.
constexpr size_t LicenseMaxSize = 16 << 10;
// Skew is how far clocks may disagree when the issue time is checked, in seconds.
constexpr int64_t LicenseSkew = 300;

// Verify is the whole check: the format and every parsing rule, the key and the signature, the
// extension, its version and the time (seconds since the epoch). An extension passes
// Keys::Trusted() and its own version; an empty version skips the range (kista's use: a licence for
// a name). It throws nothing but std::bad_alloc.
Result Verify(const std::string &token, const Keys &keys, const std::string &ext, const std::string &version,
              int64_t now);

// StatusAt is the time rows of the status table for verified claims.
Status StatusAt(const Claims &c, int64_t now);

// IsVersion reports whether a version has the form a licence's range compares ("v1.2.3").
bool IsVersion(const std::string &version);

} // namespace kista
