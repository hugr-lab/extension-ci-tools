// Checks the C++ verifier against spec 0012's licence vectors (internal/license/testdata/vectors.json,
// written by go run ./internal/license/vectorgen): each token's status, the rule an invalid one
// breaks, and the claims of the others, exactly as the Go reference verifier reads them.
//
//   kista_sdk_vectors <vectors.json>
#include "../src/json.hpp"
#include "kista/license.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

using kista::json::Kind;
using kista::json::Value;

namespace {

Value Str(const std::string &s) {
	Value v;
	v.kind = Kind::String;
	v.s = s;
	return v;
}

Value Int(int64_t n) {
	Value v;
	v.kind = Kind::Int;
	v.n = n;
	return v;
}

void Put(Value &o, const std::string &name, Value v) {
	o.members.push_back({name, std::move(v)});
}

// ClaimsJSON is the claims as the vectors write them (kista's names; holder, versions and limits
// left out when absent).
Value ClaimsJSON(const kista::Claims &c) {
	Value o;
	o.kind = Kind::Object;
	Put(o, "key", Str(c.key));
	Put(o, "issuer", Str(c.issuer));
	Put(o, "id", Str(c.id));
	Put(o, "holder_id", Str(c.holder_id));
	if (!c.holder.empty()) {
		Put(o, "holder", Str(c.holder));
	}
	Put(o, "extension", Str(c.extension));
	if (c.has_versions) {
		Value v;
		v.kind = Kind::Object;
		if (!c.versions_min.empty()) {
			Put(v, "min", Str(c.versions_min));
		}
		if (!c.versions_below.empty()) {
			Put(v, "below", Str(c.versions_below));
		}
		Put(o, "versions", v);
	}
	Put(o, "plan", Str(c.plan));
	if (!c.limits.empty()) {
		Value ls;
		ls.kind = Kind::Array;
		for (auto &l : c.limits) {
			Value e;
			e.kind = Kind::Object;
			Put(e, "name", Str(l.first));
			Value val;
			switch (l.second.kind) {
			case kista::LimitValue::Kind::Bool:
				val.kind = Kind::Bool;
				val.b = l.second.b;
				break;
			case kista::LimitValue::Kind::Int:
				val = Int(l.second.i);
				break;
			case kista::LimitValue::Kind::String:
				val = Str(l.second.s);
				break;
			}
			Put(e, "value", val);
			ls.arr.push_back(e);
		}
		Put(o, "limits", ls);
	}
	Put(o, "issued_at", Int(c.issued_at));
	Put(o, "expires_at", Int(c.expires_at));
	Put(o, "grace", Int(c.grace));
	return o;
}

// Equal compares two values; object members in any order.
bool Equal(const Value &a, const Value &b) {
	if (a.kind != b.kind) {
		return false;
	}
	switch (a.kind) {
	case Kind::Null:
		return true;
	case Kind::Bool:
		return a.b == b.b;
	case Kind::Int:
		return a.n == b.n;
	case Kind::String:
		return a.s == b.s;
	case Kind::Array:
		if (a.arr.size() != b.arr.size()) {
			return false;
		}
		for (size_t i = 0; i < a.arr.size(); i++) {
			if (!Equal(a.arr[i], b.arr[i])) {
				return false;
			}
		}
		return true;
	case Kind::Object:
		if (a.members.size() != b.members.size()) {
			return false;
		}
		for (auto &m : a.members) {
			auto o = b.Get(m.name);
			if (!o || !Equal(m.v, *o)) {
				return false;
			}
		}
		return true;
	}
	return false;
}

std::string Field(const Value &c, const char *name) {
	auto v = c.Get(name);
	return v && v->kind == Kind::String ? v->s : "";
}

} // namespace

int main(int argc, char **argv) {
	if (argc != 2) {
		std::cerr << "usage: kista_sdk_vectors <vectors.json>\n";
		return 2;
	}
	std::ifstream in(argv[1], std::ios::binary);
	std::stringstream ss;
	ss << in.rdbuf();
	Value doc;
	kista::json::Error err;
	if (!in || !kista::json::Parse(ss.str(), doc, err)) {
		std::cerr << "reading " << argv[1] << ": " << err.message << "\n";
		return 2;
	}
	kista::Keys keys;
	for (auto &k : doc.Get("keys")->arr) {
		if (!keys.Add(k.s)) {
			std::cerr << "a vectors key is not an RSA-2048 public key\n";
			return 2;
		}
	}
	// this test links kista_sdk_testkey: its key block holds the vectors' key, and no other
	for (auto &k : doc.Get("keys")->arr) {
		if (!kista::TrustsTestKey() || !kista::Keys::Trusted().Find(kista::Fingerprint(k.s))) {
			std::cerr << "kista_sdk_testkey does not trust the vectors' key\n";
			return 1;
		}
	}
	if (kista::Keys::Trusted().Size() != doc.Get("keys")->arr.size() || !kista::KeyBlockProblem().empty()) {
		std::cerr << "kista_sdk_testkey trusts " << kista::Keys::Trusted().Size() << " keys: " << kista::KeyBlockProblem()
		          << "\n";
		return 1;
	}
	int failed = 0, n = 0;
	for (auto &c : doc.Get("cases")->arr) {
		n++;
		auto name = Field(c, "name");
		auto r = kista::Verify(Field(c, "token"), keys, Field(c, "ext"), Field(c, "version"), c.Get("now")->n);
		std::string want = Field(c, "status"), wantRule = Field(c, "rule");
		std::string why;
		if (want != kista::StatusName(r.status)) {
			why = std::string("status ") + kista::StatusName(r.status) + " (" + r.rule + ": " + r.message + "), want " + want;
		} else if (r.rule != wantRule) {
			why = "rule " + r.rule + " (" + r.message + "), want " + wantRule;
		} else {
			auto claims = c.Get("claims");
			if (claims->kind == Kind::Null) {
				if (r.has_claims) {
					why = "claims for an invalid licence";
				}
			} else if (!r.has_claims || !Equal(ClaimsJSON(r.claims), *claims)) {
				why = "claims differ";
			}
		}
		if (!why.empty()) {
			failed++;
			std::cerr << "FAIL " << name << ": " << why << "\n";
		}
	}
	if (n == 0) {
		std::cerr << "no cases\n";
		return 1;
	}
	std::cout << n - failed << "/" << n << " vectors pass\n";
	return failed == 0 ? 0 : 1;
}
