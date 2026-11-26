#include "mpwsi/plain_polynomial.h"
#include "mpwsi/common.h"
#include <apsu/util/interpolate.h>
#include <seal/util/uintarithsmallmod.h>
#include <algorithm>

namespace mpwsi {
std::vector<std::uint64_t> interpolate_batch_inverse(
    const std::vector<std::uint64_t> &points,
    const std::vector<std::uint64_t> &values, const seal::Modulus &mod) {
    using namespace seal::util;
    require(points.size() == values.size(), "interpolation size mismatch");
    require(mod.is_prime(), "interpolation needs a prime field");
    const auto n = points.size();
    require(n <= 128, "interpolation exceeds supported bucket capacity");
    for (std::size_t i = 0; i < n; ++i)
        require(points[i] < mod.value() && values[i] < mod.value(),
                "noncanonical interpolation input");
    if (!n)
        return {0};
    std::vector<std::uint64_t> denominators, prefixes;
    denominators.reserve(n * (n - 1) / 2);
    prefixes.reserve(n * (n - 1) / 2);
    std::uint64_t product = 1;
    for (std::size_t j = 1; j < n; ++j)
        for (std::size_t i = 0; i < n - j; ++i) {
            const auto denominator = sub_uint_mod(points[i + j], points[i], mod);
            require(denominator != 0, "repeated interpolation point");
            denominators.push_back(denominator);
            prefixes.push_back(product);
            product = multiply_uint_mod(product, denominator, mod);
        }
    // Montgomery's batch-inversion identity: one inverse plus linear products,
    // instead of n(n-1)/2 modular exponentiations in upstream interpolation.
    auto inverse = exponentiate_uint_mod(product, mod.value() - 2, mod);
    for (std::size_t k = denominators.size(); k-- > 0;) {
        const auto denominator = denominators[k];
        denominators[k] = multiply_uint_mod(prefixes[k], inverse, mod);
        inverse = multiply_uint_mod(inverse, denominator, mod);
    }
    auto differences = values;
    std::vector<std::uint64_t> first{values[0]};
    first.reserve(n);
    std::size_t k = 0;
    for (std::size_t j = 1; j < n; ++j) {
        for (std::size_t i = 0; i < n - j; ++i)
            differences[i] = multiply_uint_mod(
                sub_uint_mod(differences[i + 1], differences[i], mod), denominators[k++], mod);
        first.push_back(differences[0]);
    }
    std::vector<std::uint64_t> result{first.back()};
    result.reserve(n);
    for (std::size_t i = n - 1; i > 0; --i) {
        apsu::util::polyn_mul_monic_monomial_inplace(result, points[i - 1], mod);
        result[0] = add_uint_mod(result[0], first[i - 1], mod);
    }
    return result;
}
}
