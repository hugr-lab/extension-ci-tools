// kista_sdk, the library an extension links, trusts no test key: a licence signed with the vectors'
// test-only key is kid_untrusted there.
#include "kista/license.hpp"

#include <iostream>

// an RSA-2048 public key with e = 3, which kista refuses
static const char *const E3Key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA1F48lOR7Kn+3Ju7Qm7BP\n"
    "AGnsL/N9cJKeSMzC4WkEX6SxBSpzfB/ILh7Ne9JHnSX6fSUgjtozfs3jYFx8CIia\n"
    "O/V7Ar5o+Rso85KN4oIT4NvnFbF0JzlcNdkZd0tZRNeosjJUzh8k9Zzszz2XC3W7\n"
    "NiDTCPJqxw5sC6JnpWvrCVcTUYJ5RkG8FoO7oJ01PJQpLl+E0BwUvu1IRBU7X7yy\n"
    "5gaUczLkbbqj1GpOHbZUH0rdAJNiuYnWj4s479QjiNfRb0w+1NXZCAiuE4fKgn5b\n"
    "h1i+T08/IcMfAtjUAXF9cNFTq8Io75DXP0U9ENAjEw2KTXxKei3lTtU3AjNg1RvZ\n"
    "fwIBAw==\n"
    "-----END PUBLIC KEY-----\n";

int main() {
	if (kista::TrustsTestKey()) {
		std::cerr << "kista_sdk trusts the test key\n";
		return 1;
	}
	// the vectors' first case, signed with the test key
	const char *token =
	    "eyJhbGciOiJSUzI1NiIsInR5cCI6Imtpc3RhLWxpY2Vuc2Urand0Iiwia2lkIjoic2hhMjU2Ojc3MGJkNGI3MTc2ZGQzMWMyYzEyM2Q2ZGM2OTg1NmZiMmEzOThl"
	    "YTgyM2RjYWM2ZjVkYjdhZjExZDEzOWQ1NTIifQ.eyJ2IjoxfQ.sig";
	auto r = kista::Verify(token, kista::Keys::Trusted(), "myext", "1.0", 0);
	if (r.status != kista::Status::Invalid) {
		std::cerr << "not refused\n";
		return 1;
	}
	std::cout << "kista_sdk trusts " << kista::Keys::Trusted().Size() << " keys, no test key\n";
	return 0;
}
