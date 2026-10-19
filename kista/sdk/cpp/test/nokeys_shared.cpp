// A shared library that links kista_sdk without kista_sdk_license_keys (the ctest
// kista_sdk_nokeys_shared): it must not link. On Linux a shared library may leave symbols undefined,
// but not a hidden one.
#include "kista/license.hpp"

bool nokeys_trusts_test_key() {
	return kista::TrustsTestKey();
}
