// The SDK's DuckDB side (spec 0012 phase 2): the licence read at load and kept current, Check, the
// table functions and usage reports.
//
// Locking: State::mu guards a state and is never held across HTTP or while opening a connection.
// DuckDB calls OnConnectionClosed with its connection lock held, so nothing there opens a
// connection.
#include "kista/kista.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/extension_manager.hpp"
#include "duckdb/main/http/http_transport_manager.hpp"
#include "duckdb/main/http/http_util.hpp"
#include "duckdb/planner/extension_callback.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace duckdb {
// DuckDB's logging macros name DuckDB's types unqualified
static void KistaWarn(ClientContext &context, const string &msg) {
	DUCKDB_LOG_WARNING(context, "%s", msg);
}
static void KistaWarn(DatabaseInstance &db, const string &msg) {
	DUCKDB_LOG_WARNING(db, "%s", msg);
}
} // namespace duckdb

namespace kista {

const std::string License::empty;

namespace {

using duckdb::ClientContext;
using duckdb::DatabaseInstance;

constexpr int64_t FetchTimeout = 5;  // seconds, no retries
constexpr int64_t SendTimeout = 2;   // a usage report: short, it may run under DuckDB's connection lock
constexpr int64_t RenewEvery = 3600; // at most one fetch an hour, but for the first use after a deferred load
constexpr int64_t SendEvery = 600;   // usage: every 10 minutes, or when a connection closes
constexpr size_t MaxEvents = 32, MaxCounters = 16;

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

// IsName is an event or counter name (internal/usage: [a-z][a-z0-9_.]{0,63}).
bool IsName(const std::string &s) {
	if (s.empty() || s.size() > 64 || s[0] < 'a' || s[0] > 'z') {
		return false;
	}
	for (char c : s) {
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.')) {
			return false;
		}
	}
	return true;
}

// IsExtension is an extension name ([a-z0-9_]{1,64}, as a licence's ext): it goes into a file
// name and a URL.
bool IsExtension(const std::string &s) {
	if (s.empty() || s.size() > 64) {
		return false;
	}
	for (char c : s) {
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
			return false;
		}
	}
	return true;
}

bool Usable(Status s) {
	return s == Status::Valid || s == Status::Grace;
}

// ModuleDir is the directory of the module this code is in: the extension's file (DuckDB records
// no install directory).
std::string ModuleDir() {
#ifdef _WIN32
	HMODULE mod = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
	                        reinterpret_cast<LPCSTR>(&ModuleDir), &mod)) {
		return "";
	}
	char path[MAX_PATH];
	DWORD n = GetModuleFileNameA(mod, path, MAX_PATH);
	if (n == 0 || n == MAX_PATH) {
		return "";
	}
	std::string p(path, n);
	auto slash = p.find_last_of("\\/");
#else
	Dl_info info;
	if (!dladdr(reinterpret_cast<void *>(&ModuleDir), &info) || !info.dli_fname) {
		return "";
	}
	std::string p(info.dli_fname);
	auto slash = p.find_last_of('/');
#endif
	return slash == std::string::npos ? "" : p.substr(0, slash);
}

std::string JSONString(const std::string &s) {
	std::string out = "\"";
	for (unsigned char c : s) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		default:
			if (c < 0x20 || c >= 0x80) {
				// names are ASCII; anything else is escaped byte by byte rather than sent as possibly
				// invalid UTF-8
				char buf[8];
				snprintf(buf, sizeof(buf), "\\u%04x", c);
				out += buf;
			} else {
				out.push_back(char(c));
			}
		}
	}
	return out + "\"";
}

struct Event {
	int64_t count = 0;
	std::map<std::string, int64_t> counters;
};

int64_t Add(int64_t a, int64_t b) {
	const int64_t max = (int64_t(1) << 53) - 1;
	return b <= 0 ? a : (a > max - b ? max : a + b);
}

// State is one extension's licence and usage in one database.
struct State {
	std::string name;
	std::mutex mu;
	// where it was installed from and what it is
	std::string repo, version, module_dir;
	bool loaded = false;
	// the licence in use
	std::string token, source, message;
	Result result;
	int64_t last_fetch = 0;
	bool fetching = false;      // a fetch runs (outside mu): no second one
	bool fetch_pending = false; // the last fetch got no answer that settles it
	// the fetch at load got no answer: the user's session may hold what it needs (its TLS settings, a
	// secret it can see), so the first Get asks once more with the user's context, and the load event
	// waits for it
	bool retry_once = false;
	bool load_pending = false;
	bool warned_grace = false;
	// usage, by the licence status at the time of the event
	std::map<std::string, std::map<std::string, Event>> events;
	int64_t last_send = 0;
	int64_t send_backoff_until = 0;

	std::string FilePath() const {
		return module_dir.empty() ? "" : module_dir + "/" + name + ".kista-license";
	}
};

std::mutex registry_mu;
std::map<std::pair<const DatabaseInstance *, std::string>, std::shared_ptr<State>> registry;

std::shared_ptr<State> Find(DatabaseInstance &db, const std::string &name) {
	std::lock_guard<std::mutex> l(registry_mu);
	auto it = registry.find({&db, name});
	return it == registry.end() ? nullptr : it->second;
}

std::string Trim(const std::string &s) {
	auto b = s.find_first_not_of(" \t\r\n"), e = s.find_last_not_of(" \t\r\n");
	return b == std::string::npos ? "" : s.substr(b, e - b + 1);
}

// CurrentStatus is the state's status now (mu held).
Status CurrentStatus(const State &s, int64_t now) {
	if (s.token.empty()) {
		return s.result.status == Status::Invalid && !s.result.rule.empty() ? Status::Invalid : Status::Missing;
	}
	return s.result.status == Status::NotCovered ? Status::NotCovered : StatusAt(s.result.claims, now);
}

// Adopt verifies a token and makes it the licence in use (mu held), unless it is invalid, or it would
// replace a usable licence with one that is not usable or is older: a stale or compromised
// repository cannot downgrade what works.
bool Adopt(State &s, const std::string &token, const std::string &source) {
	auto now = Now();
	auto r = Verify(token, Keys::Trusted(), s.name, s.version, now);
	if (r.status == Status::Invalid) {
		if (s.token.empty()) {
			s.result = r;
			s.source = source;
			s.message = "the licence from the " + source + " is invalid (" + r.rule + "): " + r.message;
		}
		return false;
	}
	if (!s.token.empty() && Usable(CurrentStatus(s, now)) &&
	    (!Usable(r.status) || r.claims.issued_at < s.result.claims.issued_at)) {
		return false;
	}
	s.token = token;
	s.source = source;
	s.result = r;
	s.message.clear();
	return true;
}

// ReadFile reads the licence beside the module, a regular file only (mu held).
void ReadFile(State &s) {
	auto path = s.FilePath();
	std::error_code ec;
	if (path.empty() || !std::filesystem::is_regular_file(path, ec)) {
		return;
	}
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		return;
	}
	std::string token(LicenseMaxSize + 2, '\0');
	in.read(&token[0], std::streamsize(token.size()));
	token.resize(size_t(in.gcount()));
	Adopt(s, Trim(token), "file");
}

// WriteFile keeps a fetched licence beside the module through a temporary file of its own (created
// exclusively, never through a link), flushed, and a rename; best effort, the directory may be
// read-only (mu held).
void WriteFile(const State &s) {
	auto path = s.FilePath();
	if (path.empty()) {
		return;
	}
	static std::atomic<uint64_t> seq {0};
	auto data = s.token + "\n";
#ifdef _WIN32
	auto tmp = path + ".tmp." + std::to_string(GetCurrentProcessId()) + "." + std::to_string(++seq);
	HANDLE h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}
	DWORD n = 0;
	bool ok = ::WriteFile(h, data.data(), DWORD(data.size()), &n, nullptr) && n == data.size() && FlushFileBuffers(h);
	CloseHandle(h);
	if (!ok || !MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		DeleteFileA(tmp.c_str());
	}
#else
	auto tmp = path + ".tmp." + std::to_string(getpid()) + "." + std::to_string(++seq);
	int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (fd < 0) {
		return;
	}
	bool ok = write(fd, data.data(), data.size()) == ssize_t(data.size()) && fsync(fd) == 0;
	ok = close(fd) == 0 && ok;
	if (!ok || std::rename(tmp.c_str(), path.c_str()) != 0) {
		unlink(tmp.c_str());
	}
#endif
}

// Session opens an HTTP session for url with the context's http secret (httpfs autoloaded for
// https, as INSTALL does). Redirects are not followed: the token goes to the repository only.
duckdb::HTTPTransportManager::Session Session(ClientContext &context, const std::string &url, int64_t timeout) {
	auto &db = DatabaseInstance::GetDatabase(context);
	if (url.compare(0, 8, "https://") == 0 && !db.ExtensionIsLoaded("httpfs")) {
		duckdb::ExtensionHelper::TryAutoLoadExtension(context, "httpfs");
	}
	auto session = db.config.GetHTTPTransportManager().CreateSession(context, url);
	auto &params = session.Parameters();
	params.timeout = uint64_t(timeout);
	params.retries = 0;
	params.follow_location = false;
	params.keep_alive = false;
	return session;
}

// Fetch asks the repository for the licence, conditionally, without holding mu. A new licence is
// adopted and kept beside the module; a failure, a 404 or an invalid answer keeps what is in use.
void Fetch(State &s, ClientContext &context) {
	std::string url, etag;
	{
		std::lock_guard<std::mutex> l(s.mu);
		if (s.repo.empty() || s.fetching) {
			return;
		}
		s.fetching = true;
		s.last_fetch = Now();
		url = s.repo + "/-/licenses/" + s.name;
		if (s.result.has_claims && !s.token.empty()) {
			etag = "\"" + s.result.claims.id + "." + std::to_string(s.result.claims.issued_at) + "\"";
		}
	}
	int status = 0;
	std::string body;
	try {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto session = Session(context, url, FetchTimeout);
		duckdb::HTTPHeaders headers(db);
		if (!etag.empty()) {
			headers.Insert("If-None-Match", etag);
		}
		bool too_big = false;
		duckdb::GetRequestInfo req(url, headers, session.Parameters(), nullptr,
		                           [&](duckdb::const_data_ptr_t data, duckdb::idx_t n) {
			                           body.append(reinterpret_cast<const char *>(data), n);
			                           too_big = body.size() > LicenseMaxSize + 2; // a licence and its newline
			                           return !too_big;
		                           });
		req.try_request = true;
		auto resp = session.Request(req);
		if (resp && !resp->HasRequestError() && !too_big) {
			status = int(resp->status);
		}
	} catch (...) {
	}
	std::lock_guard<std::mutex> l(s.mu);
	s.fetching = false;
	switch (status) {
	case 200:
		s.fetch_pending = false;
		if (Adopt(s, Trim(body), "repository")) {
			WriteFile(s);
		}
		break;
	case 304: // unchanged
	case 404: // none here: a revoked licence simply stops being renewed
		s.fetch_pending = false;
		break;
	default: // no answer, a refusal (401, 403), a server error: asked again later
		s.fetch_pending = true;
	}
}

// WithContext runs f with a connection of its own, in a transaction (there is no user query to
// ride on). Never under DuckDB's connection lock (OnConnectionClosed).
void WithContext(DatabaseInstance &db, const std::function<void(ClientContext &)> &f) {
	try {
		duckdb::Connection con(db);
		con.context->RunFunctionInTransaction([&] { f(*con.context); });
	} catch (...) {
	}
}

// CountLocked adds to an event under the licence status now (mu held).
void CountLocked(State &s, const std::string &event, const std::map<std::string, int64_t> &counters, int64_t now) {
	auto &bucket = s.events[StatusName(CurrentStatus(s, now))];
	if (bucket.size() >= MaxEvents && !bucket.count(event)) {
		return;
	}
	auto &e = bucket[event];
	e.count = Add(e.count, 1);
	for (auto &c : counters) {
		if (IsName(c.first) && (e.counters.size() < MaxCounters || e.counters.count(c.first))) {
			e.counters[c.first] = Add(e.counters[c.first], c.second);
		}
	}
}

// TakeReports builds the usage reports, one per licence status, and empties the counts (mu held).
std::vector<std::string> TakeReports(State &s, int64_t now) {
	if (s.load_pending) {
		CountLocked(s, "load", {}, now); // a deferred load is counted as it stands now
		s.load_pending = false;
	}
	s.last_send = now;
	std::vector<std::string> out;
	if (s.repo.empty()) {
		s.events.clear();
		return out;
	}
	for (auto &bucket : s.events) {
		std::string b = "{\"version\":" + JSONString(s.version) + ",\"platform\":" +
		                JSONString(duckdb::DuckDB::Platform()) +
		                ",\"duckdb_version\":" + JSONString(duckdb::DuckDB::LibraryVersion());
		if (s.result.has_claims && !s.token.empty()) {
			b += ",\"license\":" + JSONString(s.result.claims.id);
		}
		b += ",\"status\":" + JSONString(bucket.first) + ",\"events\":[";
		bool first = true;
		for (auto &e : bucket.second) {
			b += std::string(first ? "" : ",") + "{\"name\":" + JSONString(e.first) +
			     ",\"count\":" + std::to_string(e.second.count);
			first = false;
			if (!e.second.counters.empty()) {
				b += ",\"counters\":{";
				bool f2 = true;
				for (auto &c : e.second.counters) {
					b += std::string(f2 ? "" : ",") + JSONString(c.first) + ":" + std::to_string(c.second);
					f2 = false;
				}
				b += "}";
			}
			b += "}";
		}
		out.push_back(b + "]}");
	}
	s.events.clear();
	return out;
}

// Send posts a report; false when no answer came (the repository unreachable).
bool Send(ClientContext &context, const std::string &url, const std::string &body) {
	try {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto session = Session(context, url, SendTimeout);
		duckdb::HTTPHeaders headers(db);
		headers.Insert("Content-Type", "application/json");
		duckdb::PostRequestInfo req(url, headers, session.Parameters(), duckdb::const_data_ptr_cast(body.data()),
		                            body.size());
		req.try_request = true;
		auto resp = session.Request(req); // best effort: whatever the answer, the counts are gone
		return resp && !resp->HasRequestError();
	} catch (...) {
		return false;
	}
}

// SendAll sends the reports; when one gets no answer the rest are dropped, and sends wait 10
// minutes (no stall at every close while the repository is unreachable).
void SendAll(State &s, ClientContext &context, const std::vector<std::string> &bodies) {
	auto url = s.repo + "/-/usage/" + s.name;
	for (auto &b : bodies) {
		if (!Send(context, url, b)) {
			std::lock_guard<std::mutex> l(s.mu);
			s.send_backoff_until = Now() + SendEvery;
			return;
		}
	}
}

// Background sends (the 10-minute one) hold the database only while sending, and finish before the
// process exits: an atexit handler waits for them, briefly.
std::mutex inflight_mu;
std::condition_variable inflight_cv;
int inflight = 0;

void WaitInflight() {
	std::unique_lock<std::mutex> l(inflight_mu);
	inflight_cv.wait_for(l, std::chrono::seconds(SendTimeout + 1), [] { return inflight == 0; });
}

void SendInBackground(DatabaseInstance &db, std::shared_ptr<State> s, std::vector<std::string> bodies) {
	static std::once_flag once;
	std::call_once(once, [] { std::atexit(WaitInflight); });
	duckdb::weak_ptr<DatabaseInstance> weak = db.shared_from_this();
	{
		std::lock_guard<std::mutex> l(inflight_mu);
		inflight++;
	}
	std::thread([weak, s, bodies] {
		if (auto dbp = weak.lock()) {
			WithContext(*dbp, [&](ClientContext &c) { SendAll(*s, c, bodies); });
		}
		std::lock_guard<std::mutex> l(inflight_mu);
		inflight--;
		inflight_cv.notify_all();
	}).detach();
}

class Callback : public duckdb::ExtensionCallback {
public:
	explicit Callback(std::shared_ptr<State> s) : state(std::move(s)) {
	}

	void OnExtensionLoaded(DatabaseInstance &db, const std::string &name) override {
		if (name != state->name) {
			return;
		}
		try {
			{
				std::lock_guard<std::mutex> l(state->mu);
				if (state->loaded) {
					return;
				}
				state->loaded = true;
				auto info = duckdb::ExtensionManager::Get(db).GetExtensionInfo(name);
				if (info && info->install_info) {
					state->repo = info->install_info->repository_url;
					while (!state->repo.empty() && state->repo.back() == '/') {
						state->repo.pop_back();
					}
					if (state->repo.compare(0, 7, "http://") != 0 && state->repo.compare(0, 8, "https://") != 0) {
						state->repo.clear(); // a local repository: only the file
					}
					state->version = info->install_info->version;
				}
				state->module_dir = ModuleDir();
				ReadFile(*state);
			}
			WithContext(db, [&](ClientContext &c) { Fetch(*state, c); });
			std::lock_guard<std::mutex> l(state->mu);
			if (state->fetch_pending) {
				state->retry_once = state->load_pending = true;
			} else {
				CountLocked(*state, "load", {}, Now());
			}
		} catch (...) {
		}
	}

	// OnConnectionClosed sends the counts with the closing connection's context, in a transaction of
	// its own: DuckDB holds its connection lock here, so no connection can be opened. A send is short
	// (2 seconds), and skipped for 10 minutes after one got no answer.
	void OnConnectionClosed(ClientContext &context) override {
		try {
			std::vector<std::string> bodies;
			{
				std::lock_guard<std::mutex> l(state->mu);
				auto now = Now();
				if (now < state->send_backoff_until || (state->events.empty() && !state->load_pending)) {
					return;
				}
				bodies = TakeReports(*state, now);
			}
			if (!bodies.empty()) {
				context.RunFunctionInTransaction([&] { SendAll(*state, context, bodies); });
			}
		} catch (...) {
		}
	}

private:
	std::shared_ptr<State> state;
};

std::string Timestamp(int64_t s) {
	return duckdb::Timestamp::ToString(duckdb::Timestamp::FromEpochSeconds(s));
}

// The table functions' row: the licence as Get sees it at bind.
struct LicenseRow : public duckdb::TableFunctionData {
	License lic;
};

struct RowState : public duckdb::GlobalTableFunctionState {
	bool done = false;
};

// Info is a table function's extension name.
struct Info : public duckdb::TableFunctionInfo {
	std::string name;
};

} // namespace

struct Access {
	static License Make(State &s, int64_t now) {
		License lic;
		lic.name = s.name;
		lic.source = s.source;
		lic.message = s.message;
		lic.status = CurrentStatus(s, now);
		if (!s.token.empty()) {
			lic.has_claims = s.result.has_claims;
			lic.claims = s.result.claims;
		}
		return lic;
	}

	// Get is License::Get; warn: log the grace warning (for Check's callers, not the table
	// functions).
	static License Get(ClientContext &context, const std::string &name, bool warn) {
		auto s = Find(DatabaseInstance::GetDatabase(context), name);
		if (!s) {
			License lic;
			lic.name = name;
			lic.message = "kista::License::Register was not called for " + name;
			return lic;
		}
		bool fetch;
		{
			std::lock_guard<std::mutex> l(s->mu);
			auto now = Now();
			auto &c = s->result.claims;
			bool usable = Usable(CurrentStatus(*s, now));
			bool half = s->result.has_claims && now >= c.issued_at + (c.expires_at - c.issued_at) / 2;
			// once after a deferred load; then hourly while there is no answer, no usable licence, or
			// the licence is past half its lifetime
			fetch = s->retry_once || (now - s->last_fetch >= RenewEvery && (s->fetch_pending || !usable || half));
			s->retry_once = false;
		}
		if (fetch) {
			Fetch(*s, context);
		}
		std::lock_guard<std::mutex> l(s->mu);
		auto now = Now();
		if (s->load_pending && !s->fetching) {
			CountLocked(*s, "load", {}, now);
			s->load_pending = false;
		}
		auto lic = Make(*s, now);
		if (warn && lic.status == Status::Grace && !s->warned_grace) {
			s->warned_grace = true;
			duckdb::KistaWarn(context, "the licence for " + name + " is in its grace period until " +
			                               Timestamp(lic.claims.GraceUntil()) + ": ask your administrator for a renewal");
		}
		return lic;
	}
};

License License::Get(ClientContext &context, const std::string &name) {
	return Access::Get(context, name, true);
}

void License::Check() const {
	switch (status) {
	case Status::Valid:
	case Status::Grace:
		return;
	case Status::Missing:
		throw duckdb::PermissionException(message.empty() ? "no licence for " + name + ": ask your administrator, or place " +
		                                                        name + ".kista-license next to the extension"
		                                                  : message);
	case Status::Expired:
		throw duckdb::PermissionException("the licence for %s expired on %s: ask your administrator for a renewal", name,
		                                  Timestamp(claims.expires_at));
	case Status::NotYetValid:
		throw duckdb::PermissionException("the licence for %s is not yet valid (issued for %s): check this machine's clock",
		                                  name, Timestamp(claims.issued_at));
	case Status::NotCovered:
		throw duckdb::PermissionException("the licence for %s does not cover this version: ask your administrator", name);
	case Status::Invalid:
		break;
	}
	throw duckdb::PermissionException("the licence for %s is invalid: %s", name, message);
}

void Usage::Count(ClientContext &context, const std::string &name, const std::string &event,
                  const std::map<std::string, int64_t> &counters) {
	if (!IsName(event)) {
		return;
	}
	auto &db = DatabaseInstance::GetDatabase(context);
	auto s = Find(db, name);
	if (!s) {
		return;
	}
	std::vector<std::string> bodies;
	{
		std::lock_guard<std::mutex> l(s->mu);
		auto now = Now();
		CountLocked(*s, event, counters, now);
		if (s->last_send == 0) {
			s->last_send = now;
		}
		if (now - s->last_send < SendEvery || now < s->send_backoff_until) {
			return;
		}
		bodies = TakeReports(*s, now);
	}
	if (!bodies.empty()) {
		SendInBackground(db, s, std::move(bodies)); // never on the query path
	}
}

namespace {

duckdb::unique_ptr<duckdb::FunctionData> Bind(ClientContext &context, const std::string &name, bool refresh,
                                              duckdb::vector<duckdb::LogicalType> &types,
                                              duckdb::vector<duckdb::Identifier> &names) {
	if (refresh) {
		if (auto s = Find(DatabaseInstance::GetDatabase(context), name)) {
			Fetch(*s, context);
			std::lock_guard<std::mutex> l(s->mu);
			s->retry_once = false; // asked just now: Get does not ask again
		}
	}
	auto row = duckdb::make_uniq<LicenseRow>();
	row->lic = Access::Get(context, name, false);
	for (auto &col : {"status", "plan", "holder", "holder_id", "license_id", "issuer", "issued_at", "expires_at",
	                  "grace_until", "source", "limits", "message"}) {
		names.emplace_back(col);
		bool ts = std::string(col) == "issued_at" || std::string(col) == "expires_at" || std::string(col) == "grace_until";
		types.push_back(ts ? duckdb::LogicalType::TIMESTAMP : duckdb::LogicalType::VARCHAR);
	}
	return std::move(row);
}

duckdb::unique_ptr<duckdb::FunctionData> BindLicense(ClientContext &context, duckdb::TableFunctionBindInput &input,
                                                     duckdb::vector<duckdb::LogicalType> &types,
                                                     duckdb::vector<duckdb::Identifier> &names) {
	return Bind(context, input.info->Cast<Info>().name, false, types, names);
}

duckdb::unique_ptr<duckdb::FunctionData> BindRefresh(ClientContext &context, duckdb::TableFunctionBindInput &input,
                                                     duckdb::vector<duckdb::LogicalType> &types,
                                                     duckdb::vector<duckdb::Identifier> &names) {
	return Bind(context, input.info->Cast<Info>().name, true, types, names);
}

duckdb::unique_ptr<duckdb::GlobalTableFunctionState> InitRow(ClientContext &, duckdb::TableFunctionInitInput &) {
	return duckdb::make_uniq<RowState>();
}

void Emit(ClientContext &, duckdb::TableFunctionInput &input, duckdb::DataChunk &out) {
	auto &done = input.global_state->Cast<RowState>().done;
	if (done) {
		return;
	}
	done = true;
	auto &row = input.bind_data->Cast<LicenseRow>();
	auto &lic = row.lic;
	auto &c = lic.GetClaims();
	bool has = lic.HasClaims();
	auto str = [&](const std::string &v) { return has && !v.empty() ? duckdb::Value(v) : duckdb::Value(); };
	auto ts = [&](int64_t v) {
		return has ? duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromEpochSeconds(v)) : duckdb::Value();
	};
	std::string limits;
	if (has) {
		limits = "{";
		for (size_t i = 0; i < c.limits.size(); i++) {
			auto &v = c.limits[i].second;
			limits += (i ? "," : "") + JSONString(c.limits[i].first) + ":" +
			          (v.kind == LimitValue::Kind::Bool  ? std::string(v.b ? "true" : "false")
			           : v.kind == LimitValue::Kind::Int ? std::to_string(v.i)
			                                             : JSONString(v.s));
		}
		limits += "}";
	}
	duckdb::vector<duckdb::Value> values {duckdb::Value(StatusName(lic.Status())),
	                                      str(c.plan),
	                                      str(c.holder),
	                                      str(c.holder_id),
	                                      str(c.id),
	                                      str(c.issuer),
	                                      ts(c.issued_at),
	                                      ts(c.expires_at),
	                                      ts(c.GraceUntil()),
	                                      lic.Source().empty() ? duckdb::Value() : duckdb::Value(lic.Source()),
	                                      has ? duckdb::Value(limits) : duckdb::Value(),
	                                      lic.Message().empty() ? duckdb::Value() : duckdb::Value(lic.Message())};
	for (duckdb::idx_t i = 0; i < values.size(); i++) {
		out.data[i].Append(values[i]);
	}
	out.SetChildCardinality(1);
}

} // namespace

void License::Register(duckdb::ExtensionLoader &loader, const std::string &name) {
	if (!IsExtension(name)) {
		throw duckdb::InvalidInputException("kista::License::Register: \"%s\" is not an extension name", name);
	}
	auto &db = loader.GetDatabaseInstance();
	if (TrustsTestKey()) {
		duckdb::KistaWarn(db, name + " is built with the kista SDK's test key: anyone can sign a licence it accepts");
	}
	auto state = std::make_shared<State>();
	state->name = name;
	{
		std::lock_guard<std::mutex> l(registry_mu);
		registry[{&db, name}] = state;
	}
	duckdb::ExtensionCallback::Register(duckdb::DBConfig::GetConfig(db), duckdb::make_shared_ptr<Callback>(state));
	for (bool refresh : {false, true}) {
		duckdb::table_function_bind_t bind = refresh ? BindRefresh : BindLicense;
		duckdb::TableFunction f(duckdb::Identifier(name + (refresh ? "_license_refresh" : "_license")),
		                        duckdb::vector<duckdb::LogicalType>(), Emit, bind, InitRow);
		auto info = duckdb::make_shared_ptr<Info>();
		info->name = name;
		f.function_info = std::move(info);
		loader.RegisterFunction(f);
	}
}

} // namespace kista
