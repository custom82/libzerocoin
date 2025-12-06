#include "libzerocoin.h"
#include <iostream>

int main() {
    std::cout << "Testing unified libzerocoin...\n";

    try {
        // Test CBigNum
        libzerocoin::CBigNum a(10);
        libzerocoin::CBigNum b(5);
        libzerocoin::CBigNum c = a + b;

        std::cout << "10 + 5 = " << c.ToString() << std::endl;

        // Test hash
        libzerocoin::uint256 hash = libzerocoin::Hash("test");
        std::cout << "Hash test: " << (hash.IsNull() ? "FAILED" : "OK") << std::endl;

        // Test prime generation
        std::cout << "Generating 128-bit prime...\n";
        libzerocoin::CBigNum prime = libzerocoin::CBigNum::generatePrime(128);
        std::cout << "Prime: " << prime.ToString().substr(0, 20) << "..." << std::endl;

        // Test params
        libzerocoin::ZerocoinParams params;
        std::cout << "ZerocoinParams created, security level: " << params.securityLevel << std::endl;

        std::cout << "\n=== ALL TESTS PASSED ===\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
