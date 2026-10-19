# kista: the licence keys of a licensed extension (hugr-lab's fork; kista spec 0022).
#
# Included by a licensed extension's Makefile after duckdb_extension.Makefile:
#
#   include extension-ci-tools/makefiles/duckdb_extension.Makefile
#   include extension-ci-tools/makefiles/kista.Makefile
#
# KISTA_LICENSE_KEYS names one to four PEM public keys, separated by ';'. It always reaches the
# extension's CMake as -DKISTA_LICENSE_KEYS=..., which passes it to kista_sdk_license_keys; empty, the
# extension uses its committed license-key.pem. It is passed even when empty, so a build directory
# configured with keys before does not keep them. Enterest's builders set it to the extension's
# registered keys:
#
#   make release KISTA_LICENSE_KEYS='/keys/a.pem;/keys/b.pem'
ifneq ($(findstring ',$(KISTA_LICENSE_KEYS)),)
$(error KISTA_LICENSE_KEYS must not contain a single quote)
endif
EXT_FLAGS += '-DKISTA_LICENSE_KEYS=$(strip $(KISTA_LICENSE_KEYS))'
