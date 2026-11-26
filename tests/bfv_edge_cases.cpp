#include "mpwsi/bfv_polynomial.h"
#include "mpwsi/bmwg.h"
#include "mpwsi/common.h"
#include <algorithm>
#include <iostream>

using namespace mpwsi;
int main() {
    try {
        for (unsigned bits : {50, 60}) {
            Config config;
            config.plain_bits = bits;
            if (bits == 60)
                config.poly_degree = 32768;
            auto params = he_parameters(config);
            seal::SEALContext context(params, true, seal::sec_level_type::tc128);
            require(context.parameters_set(), "invalid BFV context");
            seal::KeyGenerator keygen(context);
            seal::PublicKey pk;
            seal::RelinKeys rk;
            keygen.create_public_key(pk);
            keygen.create_relin_keys(rk);
            seal::Encryptor encryptor(context, keygen.secret_key());
            seal::Decryptor decryptor(context, keygen.secret_key());
            seal::BatchEncoder encoder(context);
            auto p = params.plain_modulus().value();
            const std::size_t degree = 64, step = polynomial_step(degree);
            std::vector<std::uint64_t> x{0, 1, p - 1, random_below(p)};
            std::vector<seal::Ciphertext> query;
            for (auto exponent : polynomial_query_powers(degree)) {
                auto slots = x;
                for (std::size_t d = 1; d < exponent; ++d)
                    for (std::size_t i = 0; i < x.size(); ++i)
                        slots[i] = static_cast<__uint128_t>(slots[i]) * x[i] % p;
                seal::Plaintext plain;
                encoder.encode(slots, plain);
                seal::Ciphertext ct;
                encryptor.encrypt_symmetric(plain, ct);
                query.push_back(std::move(ct));
            }
            // Entire zero/constant matrices, only block constants, and a
            // terminal nonlinear block cover empty accumulators independently.
            for (unsigned mode = 0; mode < 5; ++mode) {
                std::vector<std::vector<std::uint64_t>> f(4, std::vector<std::uint64_t>(degree + 1)), g = f;
                for (std::size_t i = 0; i < 4; ++i) {
                    if (mode == 1) f[i][0] = g[i][0] = p - 1;
                    if (mode == 2) f[i][step] = g[i][step * 2] = random_below(p);
                    if (mode == 3) f[i][degree] = g[i][step + 1] = p - 1;
                    if (mode == 4)
                        for (std::size_t d = 0; d <= degree; ++d)
                            f[i][d] = g[i][d] = random_below(p);
                }
                auto output = evaluate_polynomials(context, pk, rk, query, f, g);
                for (unsigned k = 0; k < 2; ++k) {
                    auto budget = decryptor.invariant_noise_budget(output[k]);
                    require(budget > 0, "noise exhausted in edge case");
                    seal::Plaintext plain;
                    decryptor.decrypt(output[k], plain);
                    std::vector<std::uint64_t> actual;
                    encoder.decode(plain, actual);
                    const auto &matrix = k ? g : f;
                    for (std::size_t i = 0; i < x.size(); ++i) {
                        std::uint64_t expected = 0;
                        for (auto it = matrix[i].rbegin(); it != matrix[i].rend(); ++it)
                            expected = (static_cast<__uint128_t>(expected) * x[i] + *it) % p;
                        require(actual[i] == expected, "edge case differs from Horner");
                    }
                    require(std::all_of(actual.begin() + x.size(), actual.end(),
                                        [](auto v) { return v == 0; }), "unused slots changed");
                    std::cout << "bits=" << bits << " mode=" << mode << " output=" << k
                              << " noise_budget=" << budget << '\n';
                }
            }
        }
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
