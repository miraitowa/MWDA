#pragma once
#include <seal/seal.h>
#include <vector>

namespace mpwsi {
// Public baby-step size and the sparse powers encrypted by the receiver.
std::size_t polynomial_step(std::size_t degree);
std::vector<std::size_t> polynomial_query_powers(std::size_t degree);

// SIMD Paterson-Stockmeyer evaluation of two polynomials using shared powers.
// Each matrix contains one padded polynomial per occupied SIMD slot.
std::vector<seal::Ciphertext> evaluate_polynomials(
    const seal::SEALContext &context, const seal::PublicKey &pk,
    const seal::RelinKeys &rk, const std::vector<seal::Ciphertext> &query,
    const std::vector<std::vector<std::uint64_t>> &f,
    const std::vector<std::vector<std::uint64_t>> &g);
} // namespace mpwsi
