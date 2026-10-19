// The licence's JSON (spec 0012): stricter than RFC 8259 readers usually are, rule for rule as
// internal/license/json.go, so the Go and the C++ verifier never read one token differently.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace kista {
namespace json {

enum class Kind { Null, Bool, Int, String, Array, Object };

struct Member;

// Value is a parsed JSON value; objects keep their members in order.
struct Value {
	Kind kind = Kind::Null;
	bool b = false;
	int64_t n = 0;
	std::string s;
	std::vector<Value> arr;
	std::vector<Member> members;

	// Get returns an object's member by name, or nullptr.
	const Value *Get(const std::string &name) const;
};

struct Member {
	std::string name;
	Value v;
};

// MaxSafe is the largest integer a licence may carry (2^53-1).
constexpr int64_t MaxSafe = (int64_t(1) << 53) - 1;

// MaxDepth bounds nesting: the top-level value is level 1, no array or object deeper than 32.
constexpr int MaxDepth = 32;

// Error is a refusal with its rule (json_syntax, json_string, json_number, json_duplicate,
// json_depth) and a message.
struct Error {
	std::string rule;
	std::string message;
};

// Parse parses one JSON text; false with err set when it breaks a rule.
bool Parse(const std::string &text, Value &out, Error &err);

} // namespace json
} // namespace kista
