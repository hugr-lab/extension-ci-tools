# DuckDB's extension config for kista_demo (e2e/build-duckdb.sh): built as a loadable extension;
# never linked into DuckDB, whose STATICALLY_LINK_EXTENSIONS names core_functions only.
duckdb_extension_load(kista_demo
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    EXTENSION_VERSION 1.2.0
)
