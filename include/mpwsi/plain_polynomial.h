#pragma once
#include <seal/modulus.h>
#include <cstdint>
#include <vector>

namespace mpwsi {
// Newton interpolation with one field inversion for all divided differences.
// Coefficients are identical to the ordinary Newton construction.
std::vector<std::uint64_t> interpolate_batch_inverse(
    const std::vector<std::uint64_t> &points,
    const std::vector<std::uint64_t> &values, const seal::Modulus &mod);
}
