#include "json.hpp"

#include <set>

namespace kista {
namespace json {

const Value *Value::Get(const std::string &name) const {
	for (auto &m : members) {
		if (m.name == name) {
			return &m.v;
		}
	}
	return nullptr;
}

namespace {

struct Parser {
	const std::string &b;
	size_t i = 0;
	Error *err;

	bool Fail(const char *rule, const std::string &msg) {
		err->rule = rule;
		err->message = "json: " + msg + " at byte " + std::to_string(i);
		return false;
	}

	void Space() {
		while (i < b.size() && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r')) {
			i++;
		}
	}

	bool Literal(const char *word) {
		size_t n = std::char_traits<char>::length(word);
		if (b.size() - i >= n && b.compare(i, n, word) == 0) {
			i += n;
			return true;
		}
		return false;
	}

	bool ParseValue(int depth, Value &v) {
		if (i >= b.size()) {
			return Fail("json_syntax", "unexpected end");
		}
		char c = b[i];
		if ((c == '{' || c == '[') && depth > MaxDepth) {
			return Fail("json_depth", "nested deeper than 32 levels");
		}
		if (c == '{') {
			return Object(depth, v);
		}
		if (c == '[') {
			return Array(depth, v);
		}
		if (c == '"') {
			v.kind = Kind::String;
			return Str(v.s);
		}
		if (c == '-' || (c >= '0' && c <= '9')) {
			v.kind = Kind::Int;
			return Number(v.n);
		}
		if (Literal("true")) {
			v.kind = Kind::Bool;
			v.b = true;
			return true;
		}
		if (Literal("false")) {
			v.kind = Kind::Bool;
			return true;
		}
		if (Literal("null")) {
			v.kind = Kind::Null;
			return true;
		}
		return Fail("json_syntax", "unexpected character");
	}

	bool Object(int depth, Value &v) {
		i++; // {
		v.kind = Kind::Object;
		std::set<std::string> seen;
		Space();
		if (i < b.size() && b[i] == '}') {
			i++;
			return true;
		}
		for (;;) {
			Space();
			if (i >= b.size() || b[i] != '"') {
				return Fail("json_syntax", "expected a member name");
			}
			std::string name;
			if (!Str(name)) {
				return false;
			}
			if (!seen.insert(name).second) {
				return Fail("json_duplicate", "duplicate member \"" + name + "\"");
			}
			Space();
			if (i >= b.size() || b[i] != ':') {
				return Fail("json_syntax", "expected ':'");
			}
			i++;
			Space();
			Member m;
			m.name = std::move(name);
			if (!ParseValue(depth + 1, m.v)) {
				return false;
			}
			v.members.push_back(std::move(m));
			Space();
			if (i >= b.size()) {
				return Fail("json_syntax", "unexpected end");
			}
			if (b[i] == ',') {
				i++;
			} else if (b[i] == '}') {
				i++;
				return true;
			} else {
				return Fail("json_syntax", "expected ',' or '}'");
			}
		}
	}

	bool Array(int depth, Value &v) {
		i++; // [
		v.kind = Kind::Array;
		Space();
		if (i < b.size() && b[i] == ']') {
			i++;
			return true;
		}
		for (;;) {
			Space();
			Value e;
			if (!ParseValue(depth + 1, e)) {
				return false;
			}
			v.arr.push_back(std::move(e));
			Space();
			if (i >= b.size()) {
				return Fail("json_syntax", "unexpected end");
			}
			if (b[i] == ',') {
				i++;
			} else if (b[i] == ']') {
				i++;
				return true;
			} else {
				return Fail("json_syntax", "expected ',' or ']'");
			}
		}
	}

	static bool Digit(char c) {
		return c >= '0' && c <= '9';
	}

	bool Number(int64_t &out) {
		size_t start = i;
		bool neg = false;
		if (b[i] == '-') {
			neg = true;
			i++;
		}
		if (i >= b.size() || !Digit(b[i])) {
			return Fail("json_number", "invalid number");
		}
		if (b[i] == '0' && i + 1 < b.size() && Digit(b[i + 1])) {
			return Fail("json_number", "leading zero");
		}
		int64_t n = 0;
		while (i < b.size() && Digit(b[i])) {
			n = n * 10 + (b[i] - '0');
			if (n > MaxSafe) {
				return Fail("json_number", "integer out of range");
			}
			i++;
		}
		if (i < b.size() && (b[i] == '.' || b[i] == 'e' || b[i] == 'E')) {
			return Fail("json_number", "not an integer");
		}
		if (neg) {
			if (i - start == 2 && n == 0) {
				out = 0; // -0 is 0
				return true;
			}
			n = -n;
		}
		out = n;
		return true;
	}

	static void AppendRune(std::string &out, uint32_t r) {
		if (r < 0x80) {
			out.push_back(char(r));
		} else if (r < 0x800) {
			out.push_back(char(0xC0 | (r >> 6)));
			out.push_back(char(0x80 | (r & 0x3F)));
		} else if (r < 0x10000) {
			out.push_back(char(0xE0 | (r >> 12)));
			out.push_back(char(0x80 | ((r >> 6) & 0x3F)));
			out.push_back(char(0x80 | (r & 0x3F)));
		} else {
			out.push_back(char(0xF0 | (r >> 18)));
			out.push_back(char(0x80 | ((r >> 12) & 0x3F)));
			out.push_back(char(0x80 | ((r >> 6) & 0x3F)));
			out.push_back(char(0x80 | (r & 0x3F)));
		}
	}

	// Utf8Size is the length of the valid UTF-8 sequence at i (Go's utf8.DecodeRune: no overlong
	// forms, no surrogates, nothing beyond U+10FFFF), or 0.
	size_t Utf8Size() const {
		auto at = [&](size_t k) -> unsigned char { return k < b.size() ? (unsigned char)b[k] : 0; };
		unsigned char c0 = at(i);
		auto cont = [](unsigned char c, unsigned char lo, unsigned char hi) { return c >= lo && c <= hi; };
		if (c0 >= 0xC2 && c0 <= 0xDF) {
			return cont(at(i + 1), 0x80, 0xBF) ? 2 : 0;
		}
		if (c0 >= 0xE0 && c0 <= 0xEF) {
			unsigned char lo = c0 == 0xE0 ? 0xA0 : 0x80, hi = c0 == 0xED ? 0x9F : 0xBF;
			return cont(at(i + 1), lo, hi) && cont(at(i + 2), 0x80, 0xBF) ? 3 : 0;
		}
		if (c0 >= 0xF0 && c0 <= 0xF4) {
			unsigned char lo = c0 == 0xF0 ? 0x90 : 0x80, hi = c0 == 0xF4 ? 0x8F : 0xBF;
			return cont(at(i + 1), lo, hi) && cont(at(i + 2), 0x80, 0xBF) && cont(at(i + 3), 0x80, 0xBF) ? 4 : 0;
		}
		return 0;
	}

	bool Str(std::string &out) {
		i++; // "
		for (;;) {
			if (i >= b.size()) {
				return Fail("json_string", "unterminated string");
			}
			unsigned char c = (unsigned char)b[i];
			if (c == '"') {
				i++;
				return true;
			}
			if (c < 0x20) {
				return Fail("json_string", "control character in a string");
			}
			if (c == '\\') {
				uint32_t r;
				if (!Escape(r)) {
					return false;
				}
				if (r == 0) {
					return Fail("json_string", "U+0000 in a string");
				}
				AppendRune(out, r);
				continue;
			}
			if (c < 0x80) {
				out.push_back(char(c));
				i++;
				continue;
			}
			size_t n = Utf8Size();
			if (n == 0) {
				return Fail("json_string", "invalid UTF-8");
			}
			out.append(b, i, n);
			i += n;
		}
	}

	bool Escape(uint32_t &r) {
		i++; // backslash
		if (i >= b.size()) {
			return Fail("json_string", "unterminated escape");
		}
		char c = b[i++];
		switch (c) {
		case '"':
		case '\\':
		case '/':
			r = uint32_t(c);
			return true;
		case 'b':
			r = '\b';
			return true;
		case 'f':
			r = '\f';
			return true;
		case 'n':
			r = '\n';
			return true;
		case 'r':
			r = '\r';
			return true;
		case 't':
			r = '\t';
			return true;
		case 'u': {
			if (!Hex4(r)) {
				return false;
			}
			if (r < 0xD800 || r > 0xDFFF) {
				return true;
			}
			if (r >= 0xDC00 || i + 1 >= b.size() || b[i] != '\\' || b[i + 1] != 'u') {
				return Fail("json_string", "unpaired surrogate");
			}
			i += 2;
			uint32_t lo;
			if (!Hex4(lo)) {
				return false;
			}
			if (lo < 0xDC00 || lo > 0xDFFF) {
				return Fail("json_string", "unpaired surrogate");
			}
			r = 0x10000 + ((r - 0xD800) << 10) + (lo - 0xDC00);
			return true;
		}
		default:
			return Fail("json_string", "invalid escape");
		}
	}

	bool Hex4(uint32_t &r) {
		if (b.size() - i < 4) {
			return Fail("json_string", "short \\u escape");
		}
		r = 0;
		for (size_t k = 0; k < 4; k++) {
			char c = b[i + k];
			r <<= 4;
			if (c >= '0' && c <= '9') {
				r |= uint32_t(c - '0');
			} else if (c >= 'a' && c <= 'f') {
				r |= uint32_t(c - 'a' + 10);
			} else if (c >= 'A' && c <= 'F') {
				r |= uint32_t(c - 'A' + 10);
			} else {
				return Fail("json_string", "invalid \\u escape");
			}
		}
		i += 4;
		return true;
	}
};

} // namespace

bool Parse(const std::string &text, Value &out, Error &err) {
	Parser p {text, 0, &err};
	p.Space();
	if (!p.ParseValue(1, out)) {
		return false;
	}
	p.Space();
	if (p.i != text.size()) {
		return p.Fail("json_syntax", "data after the JSON value");
	}
	return true;
}

} // namespace json
} // namespace kista
