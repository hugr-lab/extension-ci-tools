// kista SDK (spec 0012): what a C++ DuckDB extension calls. In its Load:
//
//   kista::License::Register(loader, "myext");
//
// then, where a licence matters:
//
//   auto lic = kista::License::Get(context, "myext");   // cached; never throws for status
//   lic.Check();                                         // throws unless valid or grace
//   lic.Limit<int64_t>("max_attached_sources", 1);       // the developer's controls, with a default
//   kista::Usage::Send(context, "myext", "attach", {{"sources", 3}});  // or SendAsync
//
// Register adds myext_license() and myext_license_refresh(), and reads the licence when the
// extension finishes loading: the file myext.kista-license beside the extension's module, then the
// repository it was installed from (with the http secret INSTALL used).
#pragma once

#include "kista/license.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <limits>
#include <map>
#include <string>
#include <type_traits>

namespace kista {

class License {
public:
	// Register registers the load hook and the table functions <name>_license() and
	// <name>_license_refresh(); call it once from the extension's Load.
	static void Register(duckdb::ExtensionLoader &loader, const std::string &name);
	// Get returns the extension's licence as it stands now (the status follows the clock). It
	// fetches the licence again first when the fetch at load got no answer (once), and then at most
	// hourly while there is no usable licence or the one in use is past half its lifetime.
	static License Get(duckdb::ClientContext &context, const std::string &name);

	// Check throws a PermissionException unless the status is valid or grace (in grace it logs a
	// warning, once). The message names the extension, the status and what to do.
	void Check() const;

	kista::Status Status() const {
		return status;
	}
	// Plan is the licence's plan; "" without a valid licence.
	const std::string &Plan() const {
		return Usable() ? claims.plan : empty;
	}
	// Limit returns a limit of the licence by name, or def when the licence is not valid or in
	// grace, names no such limit, or holds another type (or an integer T cannot hold).
	template <class T>
	T Limit(const std::string &name, T def) const {
		auto v = Usable() ? claims.Limit(name) : nullptr;
		if (!v) {
			return def;
		}
		if constexpr (std::is_same<T, bool>::value) {
			return v->kind == LimitValue::Kind::Bool ? v->b : def;
		} else if constexpr (std::is_integral<T>::value) {
			if (v->kind != LimitValue::Kind::Int || v->i < int64_t(std::numeric_limits<T>::min()) ||
			    (v->i > 0 && uint64_t(v->i) > uint64_t(std::numeric_limits<T>::max()))) {
				return def;
			}
			return T(v->i);
		} else {
			static_assert(std::is_constructible<T, std::string>::value, "Limit<T>: bool, an integer type or a string");
			return v->kind == LimitValue::Kind::String ? T(v->s) : def;
		}
	}

	// The licence's claims (has_claims false when there is none, or it is invalid).
	bool HasClaims() const {
		return has_claims;
	}
	const Claims &GetClaims() const {
		return claims;
	}
	// Source is where the licence in use came from: "file", "repository", or "".
	const std::string &Source() const {
		return source;
	}
	// Message says why the status is what it is, for a user or an administrator.
	const std::string &Message() const {
		return message;
	}

private:
	friend struct Access;
	bool Usable() const {
		return status == Status::Valid || status == Status::Grace;
	}

	std::string name;
	kista::Status status = Status::Missing;
	bool has_claims = false;
	Claims claims;
	std::string source;
	std::string message;
	static const std::string empty;
};

// Usage sends usage reports to the repository the extension was installed from, with the http
// secret matching the report's URL (normally the one INSTALL used): one call, one report of one event (a count of 1) with its counters, under the
// licence status of the moment. The SDK keeps nothing: when, how often and what to aggregate is the
// extension's decision, and a report that fails is gone. Event and counter names are
// [a-z][a-z0-9_.]{0,63}, at most 16 counters, values within 0..2^53-1; a report that breaks these is
// not sent. Nothing is sent when Register was not called, the extension has no version or the extension was not installed from
// an http repository. The status is what the SDK knows at the time: after a load whose fetch was
// deferred, it settles at the first License::Get.
class Usage {
public:
	// Send sends the report now, with the caller's context (a 5-second connect and stall timeout, no
	// retries), and waits for the answer; true when the repository answered 2xx (delivered: kista
	// also answers 204 to a report it drops, an unserved version say).
	// Call it from the thread running the context's query (a function's bind or execution) or with
	// no query running, never from a ClientContextState callback (QueryEnd, say), where DuckDB holds
	// the context's lock: use SendAsync there.
	static bool Send(duckdb::ClientContext &context, const std::string &name, const std::string &event,
	                 const std::map<std::string, int64_t> &counters = {});
	// SendAsync sends the report from a thread of its own, with a connection of its own (global
	// settings and temporary or persistent secrets, not the caller's session settings or a
	// connection-scoped secret), and returns at once. With 16 of the extension's reports on their way
	// in the process, it drops this one, silently. A report keeps the database open until it is sent
	// (a database closed meanwhile closes after it); at exit the process waits up to 6 seconds for
	// them.
	static void SendAsync(duckdb::ClientContext &context, const std::string &name, const std::string &event,
	                      const std::map<std::string, int64_t> &counters = {});
};

} // namespace kista
