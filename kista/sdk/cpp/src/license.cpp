#include "kista/license.hpp"

#include "crypto.hpp"
#include "json.hpp"

namespace kista {

const char *StatusName(Status s) {
	switch (s) {
	case Status::Valid:
		return "valid";
	case Status::Grace:
		return "grace";
	case Status::Expired:
		return "expired";
	case Status::NotYetValid:
		return "not_yet_valid";
	case Status::NotCovered:
		return "not_covered";
	case Status::Invalid:
		return "invalid";
	case Status::Missing:
		return "missing";
	}
	return "invalid";
}

const LimitValue *Claims::Limit(const std::string &name) const {
	for (auto &l : limits) {
		if (l.first == name) {
			return &l.second;
		}
	}
	return nullptr;
}

namespace {

constexpr int64_t DefaultGrace = 7 * 24 * 3600;
constexpr int64_t MaxGrace = 90 * 24 * 3600;

struct Refusal {
	std::string rule;
	std::string message;
};

bool Refuse(Refusal &r, const char *rule, const std::string &message) {
	r.rule = rule;
	r.message = message;
	return false;
}

bool Lower(char c) {
	return c >= 'a' && c <= 'z';
}
bool Digit(char c) {
	return c >= '0' && c <= '9';
}
bool Upper(char c) {
	return c >= 'A' && c <= 'Z';
}

// The payload's patterns (internal/license's regular expressions, written out).
bool IsJti(const std::string &s) {
	if (s.empty() || s.size() > 64) {
		return false;
	}
	for (char c : s) {
		if (!Lower(c) && !Upper(c) && !Digit(c) && c != '_' && c != '-') {
			return false;
		}
	}
	return true;
}

bool IsExt(const std::string &s) {
	if (s.empty() || s.size() > 64) {
		return false;
	}
	for (char c : s) {
		if (!Lower(c) && !Digit(c) && c != '_') {
			return false;
		}
	}
	return true;
}

bool IsPlan(const std::string &s) {
	if (s.empty() || s.size() > 32 || !(Lower(s[0]) || Digit(s[0]))) {
		return false;
	}
	for (char c : s) {
		if (!Lower(c) && !Digit(c) && c != '_' && c != '-') {
			return false;
		}
	}
	return true;
}

bool IsLimitName(const std::string &s) {
	if (s.empty() || s.size() > 64 || !Lower(s[0])) {
		return false;
	}
	for (char c : s) {
		if (!Lower(c) && !Digit(c) && c != '_') {
			return false;
		}
	}
	return true;
}

bool IsKid(const std::string &s) {
	if (s.size() != 7 + 64 || s.compare(0, 7, "sha256:") != 0) {
		return false;
	}
	for (size_t i = 7; i < s.size(); i++) {
		if (!Digit(s[i]) && !(s[i] >= 'a' && s[i] <= 'f')) {
			return false;
		}
	}
	return true;
}

bool IsIss(const std::string &s) {
	if (s.size() > 256 || s.size() <= 8 || s.compare(0, 8, "https://") != 0) {
		return false;
	}
	for (unsigned char c : s) {
		if (c < 0x21 || c > 0x7e) {
			return false;
		}
	}
	return true;
}

// Components splits a version of the form IsVersion checks into its numbers.
std::vector<int64_t> Components(const std::string &v) {
	std::vector<int64_t> out;
	size_t i = !v.empty() && v[0] == 'v' ? 1 : 0;
	int64_t n = 0;
	for (; i <= v.size(); i++) {
		if (i == v.size() || v[i] == '.') {
			out.push_back(n);
			n = 0;
		} else {
			n = n * 10 + (v[i] - '0');
		}
	}
	return out;
}

int CompareVersions(const std::string &a, const std::string &b) {
	auto pa = Components(a), pb = Components(b);
	for (size_t i = 0; i < 4; i++) {
		int64_t x = i < pa.size() ? pa[i] : 0, y = i < pb.size() ? pb[i] : 0;
		if (x != y) {
			return x < y ? -1 : 1;
		}
	}
	return 0;
}

bool Covers(const Claims &c, const std::string &version) {
	if (!c.has_versions) {
		return true;
	}
	if (!IsVersion(version)) {
		return false;
	}
	if (!c.versions_min.empty() && CompareVersions(version, c.versions_min) < 0) {
		return false;
	}
	if (!c.versions_below.empty() && CompareVersions(version, c.versions_below) >= 0) {
		return false;
	}
	return true;
}

// Base64url decodes a part: canonical base64url without padding (no padding, whitespace, other
// alphabets or non-zero trailing bits).
bool Base64url(const std::string &in, std::string &out) {
	if (in.empty() || in.size() % 4 == 1) {
		return false;
	}
	auto val = [](char c) -> int {
		if (Upper(c)) {
			return c - 'A';
		}
		if (Lower(c)) {
			return c - 'a' + 26;
		}
		if (Digit(c)) {
			return c - '0' + 52;
		}
		if (c == '-') {
			return 62;
		}
		if (c == '_') {
			return 63;
		}
		return -1;
	};
	out.clear();
	uint32_t acc = 0;
	int bits = 0;
	for (char c : in) {
		int v = val(c);
		if (v < 0) {
			return false;
		}
		acc = (acc << 6) | uint32_t(v);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(char((acc >> bits) & 0xFF));
		}
	}
	// the bits left over must be zero (Go's Strict decoding)
	return (acc & ((1u << bits) - 1)) == 0;
}

// Str reads a string member; absent is "" unless required.
bool Str(const json::Value &o, const char *name, const char *rule, bool required, std::string &out, Refusal &r) {
	auto v = o.Get(name);
	if (!v) {
		if (required) {
			return Refuse(r, rule, std::string(name) + " is missing");
		}
		out.clear();
		return true;
	}
	if (v->kind != json::Kind::String) {
		return Refuse(r, rule, std::string(name) + " is not a string");
	}
	out = v->s;
	return true;
}

bool Int(const json::Value &o, const char *name, const char *rule, int64_t &out, Refusal &r) {
	auto v = o.Get(name);
	if (!v) {
		return Refuse(r, rule, std::string(name) + " is missing");
	}
	if (v->kind != json::Kind::Int) {
		return Refuse(r, rule, std::string(name) + " is not an integer");
	}
	out = v->n;
	return true;
}

bool ParseJSON(const std::string &text, json::Value &v, Refusal &r) {
	json::Error e;
	if (!json::Parse(text, v, e)) {
		r.rule = e.rule;
		r.message = e.message;
		return false;
	}
	return true;
}

bool Header(const std::string &raw, Claims &c, Refusal &r) {
	json::Value h;
	if (!ParseJSON(raw, h, r)) {
		return false;
	}
	if (h.kind != json::Kind::Object || h.members.size() != 3) {
		return Refuse(r, "header", "the header must have exactly alg, typ and kid");
	}
	std::string alg, typ, kid;
	if (!Str(h, "alg", "header", true, alg, r) || !Str(h, "typ", "header", true, typ, r) ||
	    !Str(h, "kid", "header", true, kid, r)) {
		return false;
	}
	if (alg != "RS256") {
		return Refuse(r, "header", "alg is not RS256");
	}
	if (typ != "kista-license+jwt") {
		return Refuse(r, "header", "typ is not kista-license+jwt");
	}
	if (!IsKid(kid)) {
		return Refuse(r, "kid", "kid is not sha256: and 64 lowercase hex digits");
	}
	c.key = kid;
	return true;
}

bool Versions(const json::Value &p, Claims &c, Refusal &r) {
	auto v = p.Get("versions");
	if (!v) {
		return true;
	}
	if (v->kind != json::Kind::Object) {
		return Refuse(r, "versions", "versions is not an object");
	}
	int n = 0;
	for (auto name : {"min", "below"}) {
		if (!v->Get(name)) {
			continue;
		}
		n++;
		std::string s;
		if (!Str(*v, name, "versions", true, s, r)) {
			return false;
		}
		if (!IsVersion(s)) {
			return Refuse(r, "versions", "version \"" + s + "\" is not a version (v1.2.3)");
		}
		(std::string(name) == "min" ? c.versions_min : c.versions_below) = s;
	}
	if (n == 0) {
		return Refuse(r, "versions", "versions names neither min nor below");
	}
	c.has_versions = true;
	return true;
}

bool Limits(const json::Value &p, Claims &c, Refusal &r) {
	auto l = p.Get("limits");
	if (!l) {
		return true;
	}
	if (l->kind != json::Kind::Object) {
		return Refuse(r, "limits", "limits is not an object");
	}
	if (l->members.size() > 64) {
		return Refuse(r, "limits", "more than 64 limits");
	}
	for (auto &m : l->members) {
		if (!IsLimitName(m.name)) {
			return Refuse(r, "limits", "limit name \"" + m.name + "\" is not [a-z][a-z0-9_]{0,63}");
		}
		LimitValue v;
		switch (m.v.kind) {
		case json::Kind::Bool:
			v.kind = LimitValue::Kind::Bool;
			v.b = m.v.b;
			break;
		case json::Kind::Int:
			v.kind = LimitValue::Kind::Int;
			v.i = m.v.n;
			break;
		case json::Kind::String:
			if (m.v.s.size() > 256) {
				return Refuse(r, "limits", "limit \"" + m.name + "\" is longer than 256 bytes");
			}
			v.kind = LimitValue::Kind::String;
			v.s = m.v.s;
			break;
		default:
			return Refuse(r, "limits", "limit \"" + m.name + "\" is not a bool, an integer or a string");
		}
		c.limits.emplace_back(m.name, std::move(v));
	}
	return true;
}

bool Payload(const std::string &raw, Claims &c, Refusal &r) {
	json::Value p;
	if (!ParseJSON(raw, p, r)) {
		return false;
	}
	if (p.kind != json::Kind::Object) {
		return Refuse(r, "payload", "the payload is not an object");
	}
	int64_t v;
	if (!Int(p, "v", "v", v, r)) {
		return false;
	}
	if (v != 1) {
		return Refuse(r, "v", "format version " + std::to_string(v) + ", want 1");
	}
	if (!Str(p, "iss", "iss", true, c.issuer, r)) {
		return false;
	}
	if (!IsIss(c.issuer)) {
		return Refuse(r, "iss", "iss is not https:// and printable ASCII, at most 256 bytes");
	}
	if (!Str(p, "jti", "jti", true, c.id, r)) {
		return false;
	}
	if (!IsJti(c.id)) {
		return Refuse(r, "jti", "jti is not [A-Za-z0-9_-]{1,64}");
	}
	if (!Str(p, "sub", "sub", true, c.holder_id, r)) {
		return false;
	}
	if (c.holder_id.empty() || c.holder_id.size() > 128) {
		return Refuse(r, "sub", "sub must be 1 to 128 bytes");
	}
	if (!Str(p, "holder", "holder", false, c.holder, r)) {
		return false;
	}
	if (c.holder.size() > 200) {
		return Refuse(r, "holder", "holder is longer than 200 bytes");
	}
	if (!Str(p, "ext", "ext", true, c.extension, r)) {
		return false;
	}
	if (!IsExt(c.extension)) {
		return Refuse(r, "ext", "ext is not an extension name");
	}
	if (!Str(p, "plan", "plan", true, c.plan, r)) {
		return false;
	}
	if (!IsPlan(c.plan)) {
		return Refuse(r, "plan", "plan is not [a-z0-9][a-z0-9_-]{0,31}");
	}
	if (!Versions(p, c, r) || !Limits(p, c, r)) {
		return false;
	}
	if (!Int(p, "iat", "iat", c.issued_at, r)) {
		return false;
	}
	if (c.issued_at < 0) {
		return Refuse(r, "iat", "iat is negative");
	}
	if (!Int(p, "exp", "exp", c.expires_at, r)) {
		return false;
	}
	if (c.expires_at <= c.issued_at) {
		return Refuse(r, "exp", "exp is not after iat");
	}
	c.grace = DefaultGrace;
	if (p.Get("grace")) {
		if (!Int(p, "grace", "grace", c.grace, r)) {
			return false;
		}
		if (c.grace < 0 || c.grace > MaxGrace) {
			return Refuse(r, "grace", "grace must be 0 to " + std::to_string(MaxGrace) + " seconds");
		}
	}
	if (c.expires_at + c.grace > json::MaxSafe) {
		return Refuse(r, "exp", "exp + grace is beyond 2^53-1");
	}
	return true;
}

Result Invalid(const Refusal &r) {
	Result res;
	res.status = Status::Invalid;
	res.rule = r.rule;
	res.message = "license: " + r.message;
	return res;
}

} // namespace

bool IsVersion(const std::string &v) {
	// ^v?(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$
	size_t i = !v.empty() && v[0] == 'v' ? 1 : 0;
	int parts = 0;
	for (;;) {
		size_t start = i;
		while (i < v.size() && Digit(v[i])) {
			i++;
		}
		size_t n = i - start;
		if (n == 0 || n > 9 || (n > 1 && v[start] == '0')) {
			return false;
		}
		parts++;
		if (i == v.size()) {
			return parts <= 4;
		}
		if (v[i] != '.' || parts == 4) {
			return false;
		}
		i++;
	}
}

Status StatusAt(const Claims &c, int64_t now) {
	if (now < c.issued_at - LicenseSkew) { // iat is not negative: no overflow, whatever now is
		return Status::NotYetValid;
	}
	if (now < c.expires_at) {
		return Status::Valid;
	}
	if (now < c.GraceUntil()) {
		return Status::Grace;
	}
	return Status::Expired;
}

Result Verify(const std::string &token, const Keys &keys, const std::string &ext, const std::string &version,
              int64_t now) {
	Refusal r;
	if (token.size() > LicenseMaxSize) {
		Refuse(r, "size", "longer than " + std::to_string(LicenseMaxSize) + " bytes");
		return Invalid(r);
	}
	std::vector<std::string> parts;
	size_t start = 0;
	for (;;) {
		size_t dot = token.find('.', start);
		parts.push_back(token.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
		if (dot == std::string::npos) {
			break;
		}
		start = dot + 1;
	}
	if (parts.size() != 3) {
		Refuse(r, "compact", "not a compact JWS (three parts)");
		return Invalid(r);
	}
	std::string raw[3];
	for (int i = 0; i < 3; i++) {
		if (!Base64url(parts[i], raw[i])) {
			Refuse(r, "base64", "part " + std::to_string(i + 1) + " is not canonical base64url without padding");
			return Invalid(r);
		}
	}
	Claims c;
	if (!Header(raw[0], c, r) || !Payload(raw[1], c, r)) {
		return Invalid(r);
	}
	auto pem = keys.Find(c.key);
	if (!pem) {
		Refuse(r, "kid_untrusted", "key " + c.key + " is not trusted");
		return Invalid(r);
	}
	if (raw[2].size() != 256) {
		Refuse(r, "signature", "the signature is not 256 bytes by an RSA-2048 key");
		return Invalid(r);
	}
	if (!crypto::VerifyRS256(*pem, parts[0] + "." + parts[1], raw[2])) {
		Refuse(r, "signature", "the signature does not verify");
		return Invalid(r);
	}
	if (c.extension != ext) {
		Refuse(r, "ext_mismatch", "for " + c.extension + ", not " + ext);
		return Invalid(r);
	}
	Result res;
	res.has_claims = true;
	res.claims = std::move(c);
	res.status = !version.empty() && !Covers(res.claims, version) ? Status::NotCovered : StatusAt(res.claims, now);
	return res;
}

} // namespace kista
