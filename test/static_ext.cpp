// A static extension library's code (the ctest "static"): it uses the SDK, and refers to nothing in
// its own key block.
#include "kista/license.hpp"

size_t static_ext_trusted_keys() {
	return kista::Keys::Trusted().Size();
}
