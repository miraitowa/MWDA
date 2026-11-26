#include "mpwsi/plain_polynomial.h"
#include "mpwsi/bmwg.h"
#include "mpwsi/common.h"
#include <apsu/util/interpolate.h>
#include <iostream>
#include <set>

using namespace mpwsi;
int main() {
    try {
        for (unsigned bits : {50, 60}) {
            Config c;
            c.plain_bits = bits;
            if (bits == 60)
                c.poly_degree = 32768;
            auto mod = he_parameters(c).plain_modulus();
            auto p = mod.value();
            require(interpolate_batch_inverse({}, {}, mod) == std::vector<std::uint64_t>{0},
                    "empty interpolation");
            for (std::size_t n : {1, 2, 8, 16, 64, 128}) {
                std::vector<std::uint64_t> x;
                std::set<std::uint64_t> seen;
                for (auto value : {std::uint64_t(0), std::uint64_t(1), p - 1})
                    if (x.size() < n && seen.insert(value).second)
                        x.push_back(value);
                while (x.size() < n) {
                    auto value = random_below(p);
                    if (seen.insert(value).second)
                        x.push_back(value);
                }
                for (unsigned trial = 0; trial < 4; ++trial) {
                    std::vector<std::uint64_t> y(n);
                    for (auto &v : y)
                        v = trial == 0 ? 0 : trial == 1 ? p - 1 : random_below(p);
                    auto actual = interpolate_batch_inverse(x, y, mod);
                    auto expected = apsu::util::newton_interpolate_polyn(x, y, mod);
                    require(actual == expected, "batched interpolation coefficient mismatch");
                    for (std::size_t i = 0; i < n; ++i) {
                        std::uint64_t evaluated = 0;
                        for (auto it = actual.rbegin(); it != actual.rend(); ++it)
                            evaluated = (static_cast<__uint128_t>(evaluated) * x[i] + *it) % p;
                        require(evaluated == y[i], "interpolation differs at input point");
                    }
                }
            }
            bool rejected = false;
            try {
                interpolate_batch_inverse({1, 1}, {0, 1}, mod);
            } catch (const std::exception &) { rejected = true; }
            require(rejected, "duplicate points must be rejected");
        }
        std::cout << "batch inverse interpolation matches upstream and input values\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
