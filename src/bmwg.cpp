#include "mpwsi/bmwg.h"
#include "mpwsi/bfv_polynomial.h"
#include "mpwsi/hashing.h"
#include "mpwsi/plain_polynomial.h"
#include <apsu/oprf/ecpoint.h>
#include <apsu/util/interpolate.h>
#include <algorithm>
#include <set>
#include <sstream>

namespace mpwsi {
namespace {
using OPoint = apsu::oprf::ECPoint;
using OScalar = OPoint::scalar_type;
template <typename T> Bytes save_seal(const T &v) {
    std::ostringstream s(std::ios::binary);
    v.save(s, seal::Serialization::compr_mode_default);
    auto b = s.str();
    return {b.begin(), b.end()};
}
template <typename T> T load_seal(const Bytes &b, const seal::SEALContext &context) {
    T v;
    std::istringstream s(std::string(b.begin(), b.end()), std::ios::binary);
    v.load(context, s);
    require(s.peek() == EOF, "trailing SEAL bytes");
    return v;
}
void put_opoint(Writer &w, const OPoint &p) {
    std::array<unsigned char, OPoint::save_size> b{};
    p.save(b);
    w.raw(b.data(), b.size());
}
OPoint get_opoint(Reader &r) {
    auto b = r.raw(OPoint::save_size);
    OPoint p;
    p.load(OPoint::point_save_span_const_type(b.data(), b.size()));
    return p;
}
std::uint64_t output_field(OPoint &p, std::uint64_t prime) {
    std::array<unsigned char, 32> h{};
    p.extract_hash(h);
    return field_hash(h, prime);
}
std::uint64_t addp(std::uint64_t a, std::uint64_t b, std::uint64_t p) {
    return (a + b) % p;
}
} // namespace
std::uint64_t field_hash(const std::array<unsigned char, 32> &h, std::uint64_t p) {
    std::uint64_t v = 0;
    for (auto x : h)
        v = static_cast<std::uint64_t>((static_cast<__uint128_t>(v) * 256 + x) % p);
    return v;
}
seal::EncryptionParameters he_parameters(const Config &c) {
    seal::EncryptionParameters p(seal::scheme_type::bfv);
    p.set_poly_modulus_degree(c.poly_degree);
    auto plain_modulus = seal::PlainModulus::Batching(c.poly_degree, c.plain_bits);
    // Sparse query powers bound multiplication depth. BFVDefault(32768) used
    // 881 bits even for this shallow circuit, inflating every key quadratically.
    // SEALContext still validates these choices against tc128 below.
    if (c.plain_bits <= 50)
        p.set_coeff_modulus(seal::CoeffModulus::Create(c.poly_degree, {55,55,55,55,55,55}));
    else if (c.poly_degree == 32768) {
        // Batching(60) returns the largest 60-bit NTT prime, which also occurs
        // in Create(..., {60,...}). Draw one extra and explicitly exclude p.
        auto coeff = seal::CoeffModulus::Create(c.poly_degree, std::vector<int>(10, 60));
        coeff.erase(std::remove_if(coeff.begin(), coeff.end(),
            [&](const auto &q) { return q.value() == plain_modulus.value(); }), coeff.end());
        coeff.resize(9);
        p.set_coeff_modulus(coeff);
    } else
        p.set_coeff_modulus(seal::CoeffModulus::BFVDefault(c.poly_degree, seal::sec_level_type::tc128));
    p.set_plain_modulus(plain_modulus);
    return p;
}
BmwgReceiverSession bmwg_receiver_begin(Network &net, unsigned peer, const Config &c,
                                       const std::vector<Bytes> &query) {
    require(query.size() == c.bins, "query size mismatch");
    auto params = he_parameters(c);
    auto p = params.plain_modulus().value();
    auto owned_context = std::make_shared<seal::SEALContext>(params, true, seal::sec_level_type::tc128);
    auto &context = *owned_context;
    require(context.parameters_set(), context.parameter_error_message());
    // Paper bMWG steps 1-2: one independent FourQ OPRF key per bin.
    std::vector<OScalar> inverses(c.bins);
    Writer request;
    request.u64(c.bins);
    for (std::size_t i = 0; i < c.bins; ++i) {
        OPoint point(query[i]);
        OScalar r;
        OPoint::MakeRandomNonzeroScalar(r);
        OPoint::InvertScalar(r, inverses[i]);
        require(point.scalar_multiply(r, false), "OPRF blinding failed");
        put_opoint(request, point);
    }
    net.send(peer, request.data);
    auto answer = net.recv(peer);
    Reader ar(answer);
    require(ar.u64() == c.bins, "OPRF response size mismatch");
    std::vector<std::uint64_t> x(c.bins);
    for (std::size_t i = 0; i < c.bins; ++i) {
        auto point = get_opoint(ar);
        require(point.scalar_multiply(inverses[i], false), "OPRF unblinding failed");
        x[i] = output_field(point, p);
    }
    ar.done();
    // A fresh BFV key pair belongs only to this receiver and this invocation.
    seal::KeyGenerator keygen(context);
    Writer keys;
    // SEAL's Serializable overload retains the PRNG seed instead of expanding
    // the random half of every key before transmission.
    keys.bytes(save_seal(keygen.create_public_key()));
    keys.bytes(save_seal(keygen.create_relin_keys()));
    net.send(peer, keys.data);
    seal::BatchEncoder encoder(context);
    seal::Encryptor encryptor(context, keygen.secret_key());
    for (std::size_t start = 0; start < c.bins; start += encoder.slot_count()) {
        auto n = std::min(c.bins - start, encoder.slot_count());
        std::vector<std::uint64_t> slots(encoder.slot_count());
        std::copy_n(x.begin() + start, n, slots.begin());
        seal::Plaintext plain;
        Writer encrypted_query;
        // As in MinBucket's query powers, this is computed locally from the
        // private OPRF output; only its fresh encryption leaves the receiver.
        for (auto exponent : polynomial_query_powers(c.capacity)) {
            for (std::size_t i = 0; i < n; ++i) {
                auto value = x[start + i];
                slots[i] = value;
                for (std::size_t d = 1; d < exponent; ++d)
                    slots[i] = static_cast<std::uint64_t>(
                        static_cast<__uint128_t>(slots[i]) * value % p);
            }
            encoder.encode(slots, plain);
            encrypted_query.bytes(save_seal(encryptor.encrypt_symmetric(plain)));
        }
        net.send(peer, encrypted_query.data);
    }
    return {std::move(owned_context), keygen.secret_key()};
}
MembershipShares bmwg_receiver_finish(Network &net, unsigned peer, const Config &c,
                                     const BmwgReceiverSession &session) {
    auto &context = *session.context;
    seal::BatchEncoder encoder(context);
    seal::Decryptor decryptor(context, session.secret_key);
    MembershipShares out{std::vector<std::uint64_t>(c.bins), std::vector<std::uint64_t>(c.bins)};
    for (std::size_t start = 0; start < c.bins; start += encoder.slot_count()) {
        const auto n = std::min(c.bins - start, encoder.slot_count());
        std::vector<std::uint64_t> slots;
        seal::Plaintext plain;
        auto response = net.recv(peer);
        Reader rr(response);
        auto f = load_seal<seal::Ciphertext>(rr.bytes(), context);
        auto g = load_seal<seal::Ciphertext>(rr.bytes(), context);
        rr.done();
        // This local check never crosses the party boundary or enters public logs.
        require(decryptor.invariant_noise_budget(f) > 0 && decryptor.invariant_noise_budget(g) > 0,
                "BFV noise budget exhausted; use a larger polynomial degree or smaller capacity");
        decryptor.decrypt(f, plain);
        encoder.decode(plain, slots);
        std::copy_n(slots.begin(), n, out.label.begin() + start);
        decryptor.decrypt(g, plain);
        encoder.decode(plain, slots);
        std::copy_n(slots.begin(), n, out.weight.begin() + start);
    }
    return out;
}
MembershipShares bmwg_receiver(Network &net, unsigned peer, const Config &c,
                               const std::vector<Bytes> &query) {
    auto session = bmwg_receiver_begin(net, peer, c, query);
    return bmwg_receiver_finish(net, peer, c, session);
}
MembershipShares bmwg_sender(Network &net, unsigned peer, const Config &c,
                             const std::vector<Record> &records,
                             const std::vector<std::vector<std::size_t>> &bins) {
    require(bins.size() == c.bins, "sender bin count mismatch");
    auto params = he_parameters(c);
    auto p = params.plain_modulus().value();
    seal::SEALContext context(params, true, seal::sec_level_type::tc128);
    require(context.parameters_set(), context.parameter_error_message());
    auto request = net.recv(peer);
    Reader qr(request);
    require(qr.u64() == c.bins, "OPRF query count mismatch");
    Writer response;
    response.u64(c.bins);
    std::vector<OScalar> keys(c.bins);
    for (std::size_t i = 0; i < c.bins; ++i) {
        OPoint::MakeRandomNonzeroScalar(keys[i]);
        auto point = get_opoint(qr);
        require(point.scalar_multiply(keys[i], true), "invalid OPRF query");
        put_opoint(response, point);
    }
    qr.done();
    net.send(peer, response.data);
    MembershipShares out{std::vector<std::uint64_t>(c.bins), std::vector<std::uint64_t>(c.bins)};
    std::vector<std::vector<std::uint64_t>> F(c.bins), G(c.bins);
    // Pad every bin to the public capacity, so response size and degree do not
    // disclose actual per-bin occupancies. Padding roots have random weights.
    for (std::size_t i = 0; i < c.bins; ++i) {
        std::vector<std::uint64_t> roots, weights;
        std::set<std::uint64_t> distinct;
        for (auto j : bins[i]) {
            auto id = encode_identifier(records[j].id);
            OPoint point(id);
            require(point.scalar_multiply(keys[i], true), "OPRF local evaluation failed");
            auto v = output_field(point, p);
            require(distinct.insert(v).second, "OPRF field collision; rerun with fresh keys");
            roots.push_back(v);
            weights.push_back(records[j].weight);
        }
        while (roots.size() < c.capacity) {
            auto v = random_below(p);
            if (distinct.insert(v).second) {
                roots.push_back(v);
                weights.push_back(random_below(p));
            }
        }
        auto f = apsu::util::polyn_with_roots(roots, params.plain_modulus());
        auto g = interpolate_batch_inverse(roots, weights, params.plain_modulus());
        g.resize(f.size());
        out.label[i] = random_below(p);
        out.weight[i] = random_below(p);
        F[i] = f;
        G[i] = f;
        F[i][0] = addp(F[i][0], out.label[i], p);
        for (std::size_t d = 0; d < g.size(); ++d)
            G[i][d] = addp(G[i][d], g[d], p);
        G[i][0] = (G[i][0] + p - out.weight[i]) % p;
    }
    auto kb = net.recv(peer);
    Reader kr(kb);
    auto pk = load_seal<seal::PublicKey>(kr.bytes(), context);
    auto rk = load_seal<seal::RelinKeys>(kr.bytes(), context);
    kr.done();
    seal::BatchEncoder encoder(context);
    for (std::size_t start = 0; start < c.bins; start += encoder.slot_count()) {
        auto n = std::min(c.bins - start, encoder.slot_count());
        auto qb = net.recv(peer);
        Reader qr(qb);
        std::vector<seal::Ciphertext> query;
        for ([[maybe_unused]] auto exponent : polynomial_query_powers(c.capacity))
            query.push_back(load_seal<seal::Ciphertext>(qr.bytes(), context));
        qr.done();
        auto values = evaluate_polynomials(context, pk, rk, query,
            {F.begin() + start, F.begin() + start + n},
            {G.begin() + start, G.begin() + start + n});
        Writer output;
        output.bytes(save_seal(values[0]));
        output.bytes(save_seal(values[1]));
        net.send(peer, output.data);
    }
    return out;
}
} // namespace mpwsi
