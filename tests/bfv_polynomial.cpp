#include "mpwsi/bfv_polynomial.h"
#include "mpwsi/bmwg.h"
#include "mpwsi/common.h"
#include <algorithm>
#include <iostream>

using namespace mpwsi;
int main() {
    try {
        Config c;
        auto params = he_parameters(c);
        seal::SEALContext context(params, true, seal::sec_level_type::tc128);
        require(context.parameters_set(), "128-bit BFV parameters rejected");
        Config wide = c;
        wide.plain_bits = 60;
        wide.poly_degree = 32768;
        seal::SEALContext wide_context(he_parameters(wide), true, seal::sec_level_type::tc128);
        require(wide_context.parameters_set(), "60-bit plaintext/coefficients must be coprime");
        seal::KeyGenerator keygen(context);
        seal::PublicKey pk;
        seal::RelinKeys rk;
        keygen.create_public_key(pk);
        keygen.create_relin_keys(rk);
        seal::BatchEncoder encoder(context);
        seal::Encryptor encryptor(context, pk);
        seal::Decryptor decryptor(context, keygen.secret_key());
        const auto p = params.plain_modulus().value();
        // Full-range coefficients and inputs, zero polynomials, exact block
        // boundaries, and a partially filled SIMD batch. Expected values come
        // from an independent plaintext Horner evaluator.
        for (std::size_t degree : {1, 2, 8, 9, 16, 32, 48, 63, 64, 65, 96, 128}) {
            std::vector<std::uint64_t> values{0, 1, p - 1, random_below(p)};
            std::vector<std::vector<std::uint64_t>> f(4), g(4);
            for (std::size_t i = 0; i < 4; ++i) {
                f[i].resize(degree + 1);
                g[i].resize(degree + 1);
                for (std::size_t d = 0; d <= degree; ++d) {
                    f[i][d] = i ? random_below(p) : 0;
                    g[i][d] = i ? random_below(p) : (d == 0 ? p - 1 : 0);
                }
            }
            seal::Plaintext plain;
            std::vector<seal::Ciphertext> query;
            for (auto exponent : polynomial_query_powers(degree)) {
                auto powers = values;
                for (std::size_t d = 1; d < exponent; ++d)
                    for (std::size_t i = 0; i < powers.size(); ++i)
                        powers[i] = static_cast<__uint128_t>(powers[i]) * values[i] % p;
                encoder.encode(powers, plain);
                seal::Ciphertext ct;
                encryptor.encrypt(plain, ct);
                query.push_back(std::move(ct));
            }
            auto results = evaluate_polynomials(context, pk, rk, query, f, g);
            for (std::size_t k = 0; k < results.size(); ++k) {
                const auto budget = decryptor.invariant_noise_budget(results[k]);
                require(budget > 0, "BFV noise exhausted at degree " + std::to_string(degree));
                decryptor.decrypt(results[k], plain);
                std::vector<std::uint64_t> actual;
                encoder.decode(plain, actual);
                const auto &matrix = k ? g : f;
                for (std::size_t i = 0; i < values.size(); ++i) {
                    std::uint64_t expected = 0;
                    for (auto it = matrix[i].rbegin(); it != matrix[i].rend(); ++it)
                        expected = (static_cast<__uint128_t>(expected) * values[i] + *it) % p;
                    require(actual[i] == expected, "encrypted polynomial differs from Horner");
                }
                require(std::all_of(actual.begin() + values.size(), actual.end(),
                                    [](auto v) { return v == 0; }), "nonzero unused SIMD slot");
                std::cout << "degree=" << degree << " polynomial=" << k
                          << " noise_budget=" << budget << '\n';
            }
        }
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
