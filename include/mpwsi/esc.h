#pragma once
#include "common.h"
#include "tahe.h"
namespace mpwsi {
// Paper ESC: CMP(p-1-v,u) -> Boolean shares -> prime-field B2A -> TEnc.
// The receiver (party 0) alone receives the reconstructed weight ciphertexts.
std::vector<Cipher> esc_convert(Network &, unsigned peer, const Config &, std::uint64_t p,
                                const std::vector<std::uint64_t> &share, const Point &pk);
void esc_boundary_test(const Config &);
} // namespace mpwsi
