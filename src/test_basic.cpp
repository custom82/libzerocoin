// test_main.cpp - Test C++20
#include "libzerocoin.hpp"
#include <iostream>
#include <cassert>

using namespace libzerocoin;

int main() {
    std::cout << "=== LibZerocoin C++20 Test ===\n\n";

    try {
        // 1. Test BigNum
        std::cout << "1. Testing BigNum...\n";
        BigNum a(123);
        BigNum b(456);
        BigNum c = a + b;
        assert(c.toHex() == "243"); // 123 + 456 = 579 = 0x243

        // 2. Test Params Generation
        std::cout << "2. Generating Zerocoin params...\n";
        auto params = ZerocoinParams::generate();
        assert(params->validate());

        // 3. Test Coin Minting
        std::cout << "3. Minting test coin...\n";
        PrivateCoin coin(params, CoinDenomination::ZQ_ONE);
        assert(coin.denomination() == CoinDenomination::ZQ_ONE);

        // 4. Test Accumulator
        std::cout << "4. Testing accumulator...\n";
        Accumulator acc(params, params->g());

        acc.accumulate(coin.publicCoin().value());
        assert(acc.coinCount() == 1);

        // 5. Test Coin Spend
        std::cout << "5. Testing coin spend...\n";
        uint256 txHash = uint256::hash("test_transaction");
        CoinSpend spend(params, coin, acc, 1, txHash);

        assert(spend.coinSerialNumber() == coin.serialNumber());

        std::cout << "\n✅ All tests passed!\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
}
