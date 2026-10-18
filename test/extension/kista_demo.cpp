// kista_demo: what a licensed extension does with the kista SDK (spec 0012 phase 2), for the e2e
// cases. kista_demo_use(sources) is its one entry point: it needs a licence (Check), reads a limit
// and counts its use.
#define DUCKDB_EXTENSION_MAIN
#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "kista/kista.hpp"

namespace duckdb {

namespace {

struct UseData : public TableFunctionData {
	int64_t sources = 0;
	int64_t max_sources = 0;
	string plan;
};

struct UseState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> UseBind(ClientContext &context, TableFunctionBindInput &input, vector<LogicalType> &types,
                                 vector<Identifier> &names) {
	auto lic = kista::License::Get(context, "kista_demo");
	lic.Check();
	auto data = make_uniq<UseData>();
	data->sources = BigIntValue::Get(input.inputs[0]);
	data->max_sources = lic.Limit<int64_t>("max_attached_sources", 1);
	data->plan = lic.Plan();
	if (data->sources > data->max_sources) {
		throw PermissionException("kista_demo: plan %s allows %d sources", data->plan, data->max_sources);
	}
	kista::Usage::Count(context, "kista_demo", "attach", {{"sources", data->sources}});
	names.emplace_back("plan");
	types.push_back(LogicalType::VARCHAR);
	names.emplace_back("max_attached_sources");
	types.push_back(LogicalType::BIGINT);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> UseInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<UseState>();
}

void UseFunc(ClientContext &, TableFunctionInput &input, DataChunk &out) {
	auto &done = input.global_state->Cast<UseState>().done;
	if (done) {
		return;
	}
	done = true;
	auto &data = input.bind_data->Cast<UseData>();
	out.data[0].Append(Value(data.plan));
	out.data[1].Append(Value::BIGINT(data.max_sources));
	out.SetChildCardinality(1);
}

} // namespace

static void LoadInternal(ExtensionLoader &loader) {
	kista::License::Register(loader, "kista_demo");
	loader.RegisterFunction(TableFunction("kista_demo_use", {LogicalType::BIGINT}, UseFunc, UseBind, UseInit));
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(kista_demo, loader) {
	duckdb::LoadInternal(loader);
}
}
