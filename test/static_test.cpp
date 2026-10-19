// A binary that links a static library with keys (kista_sdk_static_ext) links, and trusts the
// library's one key.
#include "kista/license.hpp"

#include <iostream>

size_t static_ext_trusted_keys();

int main() {
	if (static_ext_trusted_keys() != 1 || kista::TrustsTestKey()) {
		std::cerr << "the static library's block is not the one trusted\n";
		return 1;
	}
	std::cout << "the static library's block is linked and trusted\n";
	return 0;
}
