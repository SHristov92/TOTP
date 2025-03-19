/*
 * main.cpp
 *
 *  Created on: Mar 19, 2025
 *      Author: shristov
 */

#include <iostream>
#include <iomanip>
#include <ctime>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <vector>

class TOTPGenerator {
public:
    TOTPGenerator(const std::string& base32Secret, int digits = 6, int interval = 30)
        : secret(decodeBase32(base32Secret)), codeDigits(digits), timeStep(interval) {}

    uint32_t generateOTP(time_t forTime = std::time(nullptr)) {
        uint64_t counter = forTime / timeStep;
        std::vector<unsigned char> hash = hmac_sha1(secret, counter);
        return truncate(hash) % static_cast<uint32_t>(std::pow(10, codeDigits));
    }

private:
    std::vector<unsigned char> secret;
    int codeDigits;
    int timeStep;

    // --- HMAC-SHA1 ---
    std::vector<unsigned char> hmac_sha1(const std::vector<unsigned char>& key, uint64_t counter) {
        unsigned char counterBytes[8];
        for (int i = 7; i >= 0; --i) {
            counterBytes[i] = counter & 0xFF;
            counter >>= 8;
        }

        unsigned char* result;
        unsigned int len = 20;
        result = HMAC(EVP_sha1(), key.data(), key.size(), counterBytes, 8, nullptr, nullptr);

        return std::vector<unsigned char>(result, result + len);
    }

    // --- Dynamic Truncation (RFC 4226) ---
    uint32_t truncate(const std::vector<unsigned char>& hash) {
        int offset = hash[hash.size() - 1] & 0x0F;
        uint32_t bin_code = (hash[offset] & 0x7F) << 24 |
                            (hash[offset + 1] & 0xFF) << 16 |
                            (hash[offset + 2] & 0xFF) << 8 |
                            (hash[offset + 3] & 0xFF);
        return bin_code;
    }

    // --- Base32 Decoder (RFC 4648) ---
    std::vector<unsigned char> decodeBase32(const std::string& base32) {
        static const std::string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::vector<unsigned char> output;
        int buffer = 0, bitsLeft = 0;

        for (char ch : base32) {
            if (ch == '=' || ch == ' ') continue;
            ch = toupper(ch);
            size_t index = base32Chars.find(ch);
            if (index == std::string::npos) continue;

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                output.push_back((buffer >> bitsLeft) & 0xFF);
            }
        }
        return output;
    }
};

class TOTPVerifier {
public:
    TOTPVerifier(const std::string& base32Secret, int digits = 6, int interval = 30, int allowedWindow = 1)
        : generator(base32Secret, digits, interval), timeStep(interval), window(allowedWindow) {}

    bool verify(uint32_t code, time_t forTime = std::time(nullptr)) {
        for (int i = -window; i <= window; ++i) {
            if (generator.generateOTP(forTime + i * timeStep) == code)
                return true;
        }
        return false;
    }

private:
    TOTPGenerator generator;
    int timeStep;
    int window;
};

// --- Example Usage ---

int main() {
    std::string base32Secret = "JBSWY3DPEHPK3PXP"; // Example secret (Base32 for "Hello!")
    std::string accountName = "john@example.com";
    std::string issuer = "MyService";

    TOTPGenerator generator(base32Secret);
    TOTPVerifier verifier(base32Secret);

    // --- Construct otpauth URI ---
    std::string otpUri = "otpauth://totp/" + issuer + ":" + accountName +
                         "?secret=" + base32Secret + "&issuer=" + issuer;

    std::cout << "\n🔐 Scan this QR code with Google Authenticator:\n\n";

    // --- Use qrencode to print it to the terminal ---
    std::string cmd = "qrencode -t ANSIUTF8 \"" + otpUri + "\"";
    system(cmd.c_str());

    std::cout << "\n🔑 Or manually enter secret: " << base32Secret << "\n";

    // --- TOTP Generation and Verification ---
    uint32_t code = generator.generateOTP();
    std::cout << "\nGenerated OTP: " << std::setw(6) << std::setfill('0') << code << std::endl;

    std::cout << "Enter code to verify: ";
    uint32_t userCode;
    std::cin >> userCode;

    if (verifier.verify(userCode)) {
        std::cout << "✅ Code is valid.\n";
    } else {
        std::cout << "❌ Code is invalid.\n";
    }

    return 0;
}


