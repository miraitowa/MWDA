#include "mpwsi/bfv_polynomial.h"
#include "mpwsi/common.h"
#include <algorithm>
#include <bit>

namespace mpwsi {
std::size_t polynomial_step(std::size_t degree) {
    std::size_t step = 1;
    while (step * step < degree + 1)
        ++step;
    return step;
}
namespace {
// Select the smallest public source-power set whose pairwise sums cover every
// required exponent. As in MinBucket's powers DAG, this trades a few encrypted
// query powers for less homomorphic multiplication depth. Capacity <=128 makes
// each search at most 2^11 tiny public subsets, with no secret-dependent choice.
std::vector<std::size_t> depth_one_basis(std::size_t maximum) {
    if (!maximum)
        return {};
    require(maximum <= 11, "unsupported polynomial exponent bound");
    unsigned best = (1U << maximum) - 1;
    for (unsigned mask = 1; mask < (1U << maximum); mask += 2) {
        if (std::popcount(mask) >= std::popcount(best))
            continue;
        bool complete = true;
        for (unsigned d = 1; d <= maximum && complete; ++d) {
            bool covered = mask & (1U << (d - 1));
            for (unsigned a = 1; a <= d / 2 && !covered; ++a)
                covered = (mask & (1U << (a - 1))) && (mask & (1U << (d - a - 1)));
            complete = covered;
        }
        if (complete)
            best = mask;
    }
    std::vector<std::size_t> result;
    for (std::size_t d = 1; d <= maximum; ++d)
        if (best & (1U << (d - 1)))
            result.push_back(d);
    return result;
}
}
std::vector<std::size_t> polynomial_query_powers(std::size_t degree) {
    require(degree >= 1 && degree <= 128, "polynomial degree must be in [1,128]");
    const auto step = polynomial_step(degree);
    auto powers = depth_one_basis(std::min(step - 1, degree));
    for (auto exponent : depth_one_basis(degree / step))
        powers.push_back(step * exponent);
    return powers;
}

std::vector<seal::Ciphertext> evaluate_polynomials(
    const seal::SEALContext &context, const seal::PublicKey &pk,
    const seal::RelinKeys &rk, const std::vector<seal::Ciphertext> &query,
    const std::vector<std::vector<std::uint64_t>> &f,
    const std::vector<std::vector<std::uint64_t>> &g) {
    require(!f.empty() && f.size() == g.size() && f[0].size() >= 2,
            "invalid polynomial matrices");
    const auto degree = f[0].size() - 1, step = polynomial_step(degree);
    seal::BatchEncoder encoder(context);
    require(f.size() <= encoder.slot_count(), "too many polynomial slots");
    for (std::size_t i = 0; i < f.size(); ++i)
        require(f[i].size() == degree + 1 && g[i].size() == degree + 1,
                "inconsistent polynomial degrees");
    seal::Evaluator eval(context);
    seal::Encryptor encryptor(context, pk);
    const auto low_count = std::min(step - 1, degree), high_count = degree / step;
    std::vector<seal::Ciphertext> low(low_count + 1), high(high_count + 1);
    const auto source_powers = polynomial_query_powers(degree);
    require(query.size() == source_powers.size(), "incorrect encrypted query power count");
    const auto &x = query[0];
    for (std::size_t i = 0; i < query.size(); ++i) {
        require(query[i].parms_id() == x.parms_id(), "inconsistent query levels");
        auto power = source_powers[i];
        if (power < step)
            low[power] = query[i];
        else
            high[power / step] = query[i];
    }
    auto extend = [&](auto &powers) {
        std::vector<std::size_t> depth(powers.size());
        for (std::size_t d = 2; d < powers.size(); ++d) {
            if (powers[d].size())
                continue;
            std::size_t a = 1, b = d - 1;
            for (std::size_t candidate = 2; candidate <= d / 2; ++candidate)
                if (std::max(depth[candidate], depth[d - candidate]) <
                    std::max(depth[a], depth[b])) {
                    a = candidate;
                    b = d - candidate;
                }
            depth[d] = 1 + std::max(depth[a], depth[b]);
            if (a == b)
                eval.square(powers[a], powers[d]);
            else
                eval.multiply(powers[a], powers[b], powers[d]);
            eval.relinearize_inplace(powers[d], rk);
        }
    };
    extend(low);
    extend(high);
    // Drop limbs only after computing the shared powers. The public depth-one
    // basis bounds this expansion before the terminal block products. Wider
    // plaintexts retain their original modulus-switch schedule.
    auto low_level = context.get_context_data(x.parms_id());
    if (low_level->parms().plain_modulus().bit_count() <= 50 && degree <= 128)
        while (low_level->parms().coeff_modulus().size() > 4)
            low_level = low_level->next_context_data();
    auto high_level = low_level;
    if (high_count && high_level->parms().plain_modulus().bit_count() <= 50 && degree <= 128)
        while (high_level->parms().coeff_modulus().size() > 3)
            high_level = high_level->next_context_data();
    const auto low_id = low_level->parms_id(), result_id = high_level->parms_id();
    // Transform each low power once, shared by both F and G. Repeating this
    // transform for every coefficient dominated the former direct evaluation.
    for (std::size_t d = 1; d < low.size(); ++d) {
        eval.mod_switch_to_inplace(low[d], low_id);
        eval.transform_to_ntt_inplace(low[d]);
    }
    for (std::size_t d = 1; d < high.size(); ++d)
        eval.mod_switch_to_inplace(high[d], result_id);
    std::vector<seal::Ciphertext> results;
    for (const auto *matrix : {&f, &g}) {
        // Match MinBucket's split: accumulate nonconstant block products,
        // relinearize their sum once, and add block constants as linear terms.
        // No independently encrypted constant is needed in every inner block.
        seal::Ciphertext products, linear;
        auto accumulate = [&](seal::Ciphertext &sum, seal::Ciphertext term) {
            if (!sum.size())
                sum = std::move(term);
            else
                eval.add_inplace(sum, term);
        };
        std::vector<std::uint64_t> slots(encoder.slot_count());
        auto coefficient = [&](std::size_t d) {
            std::fill(slots.begin(), slots.end(), 0);
            for (std::size_t i = 0; i < matrix->size(); ++i)
                slots[i] = (*matrix)[i][d];
            seal::Plaintext plain;
            encoder.encode(slots, plain);
            return plain;
        };
        for (std::size_t j = 0; j <= high_count; ++j) {
            const auto base = j * step;
            seal::Ciphertext inner;
            for (std::size_t d = 1; d < step && base + d <= degree; ++d) {
                auto plain = coefficient(base + d);
                if (plain.is_zero())
                    continue;
                eval.transform_to_ntt_inplace(plain, low_id);
                seal::Ciphertext term;
                eval.multiply_plain(low[d], plain, term);
                accumulate(inner, std::move(term));
            }
            if (inner.size()) {
                eval.transform_from_ntt_inplace(inner);
                eval.mod_switch_to_inplace(inner, result_id);
                if (j) {
                    eval.multiply_inplace(inner, high[j]);
                    accumulate(products, std::move(inner));
                } else
                    accumulate(linear, std::move(inner));
            }
            if (j) {
                auto plain = coefficient(base);
                if (!plain.is_zero()) {
                    seal::Ciphertext term;
                    eval.multiply_plain(high[j], plain, term);
                    accumulate(linear, std::move(term));
                }
            }
        }
        // All products are terminal and have size at most three. Adding them
        // first permits one relinearization per output instead of per block.
        if (products.size()) {
            eval.relinearize_inplace(products, rk);
            accumulate(linear, std::move(products));
        }
        seal::Ciphertext result = std::move(linear);
        if (!result.size())
            encryptor.encrypt_zero(result_id, result);
        auto constant = coefficient(0);
        if (!constant.is_zero())
            eval.add_plain_inplace(result, constant);
        // Keep the original algebraic rerandomization. This does not establish
        // circuit privacy (the existing implementation limitation still applies).
        seal::Ciphertext zero;
        encryptor.encrypt_zero(result_id, zero);
        eval.add_inplace(result, zero);
        // The receiver only decrypts: carrying unused RNS limbs over the wire
        // serves no purpose. Retain two limbs for a comfortable rounding margin.
        auto level = context.get_context_data(result.parms_id());
        while (level->parms().coeff_modulus().size() > 2) {
            eval.mod_switch_to_next_inplace(result);
            level = context.get_context_data(result.parms_id());
        }
        results.push_back(std::move(result));
    }
    return results;
}
} // namespace mpwsi
