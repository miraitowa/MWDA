#include "mpwsi/bmwg.h"
#include "mpwsi/hashing.h"
#include "mpwsi/tahe.h"
#include <apsu/util/interpolate.h>
#include <apsu/oprf/ecpoint.h>
#include <algorithm>
#include <iostream>
#include <set>

using namespace mpwsi;
int main() {
    try {
        using OP = apsu::oprf::ECPoint;
        for (unsigned i = 0; i < 16; ++i) {
            auto item = encode_identifier("oprf-test-" + std::to_string(i));
            OP blinded(item), direct(item);
            OP::scalar_type blind, inverse, key;
            OP::MakeRandomNonzeroScalar(blind);
            OP::InvertScalar(blind, inverse);
            OP::MakeRandomNonzeroScalar(key);
            require(blinded.scalar_multiply(blind, false), "OPRF hash/blind");
            require(blinded.scalar_multiply(key, true), "OPRF evaluate");
            require(blinded.scalar_multiply(inverse, false), "OPRF unblind");
            require(direct.scalar_multiply(key, true), "OPRF direct");
            std::array<unsigned char, 32> a{}, b{};
            blinded.extract_hash(a);
            direct.extract_hash(b);
            require(a == b, "OPRF direct/oblivious consistency");
        }
        // Algebra in q must remain correct near q, not merely for tiny weights.
        auto r = Scalar::random();
        require((r + Scalar(1)) - r == Scalar(1), "scalar addition");
        require((Scalar() - Scalar(1)) + Scalar(1) == Scalar(), "prime wrap");
        auto s1 = Scalar::random(), s2 = Scalar::random(), s3 = Scalar::random();
        auto pk = Point::generator(s1) + Point::generator(s2) + Point::generator(s3);
        auto ct = add(encrypt(pk, Scalar(77)), encrypt(pk, Scalar(23)));
        ct = rerandomize(pk, ct);
        auto plain = combine(
            ct, {partial_decrypt(s1, ct), partial_decrypt(s2, ct), partial_decrypt(s3, ct)});
        require(plain == Point::generator(Scalar(100)), "threshold addition/decryption");
        require(!(combine(ct, {partial_decrypt(s1, ct), partial_decrypt(s2, ct)}) == plain),
                "missing threshold share");
        auto scaled = scale(ct, Scalar() - Scalar(1));
        require(combine(scaled, {partial_decrypt(s1, scaled), partial_decrypt(s2, scaled),
                                 partial_decrypt(s3, scaled)}) ==
                    Point::generator(Scalar() - Scalar(100)),
                "negative scalar");
        BoundedDlog dl(500);
        for (auto n : {0ULL, 1ULL, 99ULL, 500ULL})
            require(dl.decode(Point::generator(Scalar(n))) == n, "bounded decode");
        require(!dl.decode(Point::generator(Scalar(501))), "outside valid domain");
        require(!dl.decode(Point::generator(Scalar() - Scalar(1))),
                "negative outside valid domain");
        auto packed = pack_ciphers({ct, scaled});
        auto unpacked = unpack_ciphers(packed, 2);
        require(unpacked[0].r == ct.r && unpacked[1].s == scaled.s, "cipher serialization");
        bool rejected = false;
        try {
            unpack_ciphers(packed, 3);
        } catch (...) {
            rejected = true;
        }
        require(rejected, "wrong length must be rejected");
        // bMWG polynomial equations, including empty real bin padding semantics.
        seal::Modulus p(65537);
        std::vector<std::uint64_t> x{7, 31, 101}, weights{0, 37, 100};
        auto f = apsu::util::polyn_with_roots(x, p);
        auto g = apsu::util::newton_interpolate_polyn(x, weights, p);
        auto eval = [&](const std::vector<std::uint64_t> &a, std::uint64_t v) {
            std::uint64_t out = 0;
            for (auto it = a.rbegin(); it != a.rend(); ++it)
                out = (out * v + *it) % p.value();
            return out;
        };
        for (std::size_t i = 0; i < x.size(); ++i) {
            require(eval(f, x[i]) == 0, "membership polynomial root");
            require(eval(g, x[i]) == weights[i], "interpolated weight");
            auto s = 200ULL, u = 65000ULL;
            auto t = (eval(f, x[i]) + s) % p.value();
            auto v = (eval(f, x[i]) + eval(g, x[i]) + p.value() - u) % p.value();
            require(t == s && (u + v) % p.value() == weights[i], "bMWG shares");
        }
        require(eval(f, 5) != 0, "nonmember membership polynomial");
        std::vector<Record> records;
        for (unsigned i = 0; i < 300; ++i)
            records.push_back({"ID_" + std::to_string(i), i % 101, ""});
        auto table = cuckoo_hash(records, 512);
        auto simple = simple_hash(records, table.seed, 512, 32);
        std::set<std::size_t> seen;
        for (std::size_t b = 0; b < table.records.size(); ++b)
            if (table.records[b]) {
                auto i = *table.records[b];
                require(seen.insert(i).second, "duplicate cuckoo entry");
                require(std::find(simple[b].begin(), simple[b].end(), i) != simple[b].end(),
                        "cuckoo/simple disagreement");
            }
        require(seen.size() == records.size(), "lost cuckoo entry");
        auto q = query_identifiers(table, records);
        require(q.size() == 512, "dummy padding count");
        require(cuckoo_hash({}, 8).records.size() == 8, "empty input hashing");
        // CJWA cancels exactly on all-match inputs and hides nonmatches through
        // an independently contributed alpha. This is algebra, not a security proof.
        auto d = subtract(encrypt(pk, Scalar(123)), encrypt(pk, Scalar(123)));
        auto mask = scale(d, Scalar::random());
        auto w = add(encrypt(pk, Scalar(200)), mask);
        require(combine(w, {partial_decrypt(s1, w), partial_decrypt(s2, w),
                            partial_decrypt(s3, w)}) == Point::generator(Scalar(200)),
                "CJWA match cancellation");
        std::cout << "PASS: scalar field, threshold HE, bounded decoding, serialization, bMWG "
                     "polynomials, cuckoo/simple hashing, CJWA algebra\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
