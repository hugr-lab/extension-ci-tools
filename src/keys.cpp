#include "kista/license.hpp"

#include "crypto.hpp"

namespace kista {

// The licence keys this build trusts (spec 0012): the issuer's, compiled in; no run-time setting
// adds one. Enterest's published keys go here as they are published; until then a release build
// trusts none, and every licence is invalid (kid_untrusted).
static const char *const kIssuerKeys[] = {
    nullptr,
};

#ifdef KISTA_SDK_TEST_KEY
// The licence vectors' test-only key (internal/license/testdata/test-only-2048.pem): only in the
// kista_sdk_testkey library, which tests link; never in kista_sdk.
static const char *const kTestKey = "-----BEGIN PUBLIC KEY-----\n"
                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqKRegJpXYBCx8XPiwUj\n"
                                    "exoqSzmtQrAm5/sUWlNVq6Da0XiOqVeaXMQBw1JU9UN900g9YFxDeJduHJjX/Q2e\n"
                                    "3jbcAn3ygYyK5fp63JntskqSb4auV16AFDEVDonTOvTrSWmjD7JeQyvNHGHITNhz\n"
                                    "Qjdwrj5rYYR98mCOsvI5JRjw9UPOfJou/0K03Xl+m9I9Q9z6YrMm5XEpSJN0d70g\n"
                                    "792G7fmdydTfNzAinacYDEOHnUOnkecIUk4N5EakAMNLGsqNuLG6s7WklXQY2w9v\n"
                                    "iiR/JY2uCMf0RIrjMvAgdDUQ5L3auWQHI7FlHBgwsGvDsL4PYp7Iu+MTjBDfL7ci\n"
                                    "QQIDAQAB\n"
                                    "-----END PUBLIC KEY-----\n";
#endif

bool TrustsTestKey() {
#ifdef KISTA_SDK_TEST_KEY
	return true;
#else
	return false;
#endif
}

const Keys &Keys::Trusted() {
	static const Keys keys = [] {
		Keys k;
		for (auto pem : kIssuerKeys) {
			if (pem) {
				k.Add(pem);
			}
		}
#ifdef KISTA_SDK_TEST_KEY
		k.Add(kTestKey);
#endif
		return k;
	}();
	return keys;
}

std::string Fingerprint(const std::string &pem) {
	std::string sum;
	try {
		if (!crypto::IsRSA2048(pem)) {
			return "";
		}
		auto der = crypto::Der(pem);
		// e = 65537, as kista requires (extfile.CheckKey): an RSA SPKI ends with its exponent,
		// INTEGER 65537 (02 03 01 00 01)
		static const std::string e65537("\x02\x03\x01\x00\x01", 5);
		if (der.size() < e65537.size() || der.compare(der.size() - e65537.size(), e65537.size(), e65537) != 0) {
			return "";
		}
		sum = crypto::Sha256(der);
	} catch (const std::exception &) {
		return "";
	}
	static const char hex[] = "0123456789abcdef";
	std::string out = "sha256:";
	for (unsigned char c : sum) {
		out.push_back(hex[c >> 4]);
		out.push_back(hex[c & 0xF]);
	}
	return out;
}

bool Keys::Add(const std::string &pem) {
	auto kid = Fingerprint(pem);
	if (kid.empty()) {
		return false;
	}
	by_kid[kid] = pem;
	return true;
}

const std::string *Keys::Find(const std::string &kid) const {
	auto it = by_kid.find(kid);
	return it == by_kid.end() ? nullptr : &it->second;
}

} // namespace kista
