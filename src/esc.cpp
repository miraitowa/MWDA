#include "mpwsi/esc.h"
#include "mpwsi/bmwg.h"
#include <Millionaire/millionaire.h>
#include <cstring>
#include <fstream>

namespace mpwsi {
namespace {
// AuxProtocols::B2A works in Z_(2^l), not in the 256-bit prime field Z_q.
// This adapter uses EzPC's real IKNP chosen-message OT and implements:
// Alice: r <- Z_q, M_b = (x_A XOR b) - r (mod q), output r.
// Bob:   receive M_(x_B), output that scalar. Two 128-bit OT blocks carry
// each 256-bit canonical residue; both choices are the same secret bit.
std::vector<Scalar> b2a_prime(sci::OTPack &ot, int role, const std::vector<std::uint8_t> &bits) {
    auto n = bits.size();
    std::vector<Scalar> result(n);
    if (role == sci::ALICE) {
        std::vector<sci::block128> m0(2 * n), m1(2 * n);
        for (std::size_t i = 0; i < n; ++i) {
            require(bits[i] <= 1, "invalid Boolean share");
            result[i] = Scalar::random();
            auto a = (Scalar(bits[i]) - result[i]).encode();
            auto b = (Scalar(1 - bits[i]) - result[i]).encode();
            std::memcpy(&m0[2 * i], a.data(), 32);
            std::memcpy(&m1[2 * i], b.data(), 32);
        }
        ot.iknp_straight->send(m0.data(), m1.data(), static_cast<int>(2 * n));
    } else {
        std::unique_ptr<bool[]> choices(new bool[2 * n]);
        std::vector<sci::block128> msgs(2 * n);
        for (std::size_t i = 0; i < n; ++i) {
            require(bits[i] <= 1, "invalid Boolean share");
            choices[2 * i] = choices[2 * i + 1] = bits[i] != 0;
        }
        ot.iknp_straight->recv(msgs.data(), choices.get(), static_cast<int>(2 * n));
        for (std::size_t i = 0; i < n; ++i) {
            Bytes b(32);
            std::memcpy(b.data(), &msgs[2 * i], 32);
            result[i] = Scalar::decode(b);
        }
    }
    return result;
}
} // namespace
std::vector<Cipher> esc_convert(Network &net, unsigned peer, const Config &c, std::uint64_t p,
                                const std::vector<std::uint64_t> &share, const Point &pk) {
    require(share.size() == c.bins && c.bins <= INT32_MAX / 2, "ESC input size mismatch");
    bool receiver = c.party == 0;
    int role = receiver ? sci::ALICE : sci::BOB;
    unsigned sender = receiver ? peer : c.party;
    // Dedicated, nonoverlapping SCI ports. IOPack also uses +50 and +100.
    sci::IOPack io(role, c.base_port + 1000 + sender * 200, c.hosts[0]);
    sci::OTPack ot(&io, role, true);
    MillionaireProtocol mill(role, &io, &ot, c.plain_bits, 4);
    std::vector<std::uint64_t> input(c.bins);
    std::vector<std::uint8_t> boolean(c.bins);
    for (std::size_t i = 0; i < c.bins; ++i) {
        require(share[i] < p, "noncanonical bMWG weight share");
        input[i] = receiver ? p - 1 - share[i] : share[i];
    }
    // false means strict a < b, including correct equality/boundary behavior.
    mill.compare(boolean.data(), input.data(), static_cast<int>(c.bins), c.plain_bits, false, false,
                 4);
    auto arithmetic = b2a_prime(ot, role, boolean);
    io.io->flush();
    io.io_rev->flush();
    io.io_GC->flush();
    net.add_sci_bytes(io.get_comm());
    std::vector<Cipher> local;
    local.reserve(c.bins);
    for (std::size_t i = 0; i < c.bins; ++i) {
        auto z = Scalar(share[i]) - Scalar(p) * arithmetic[i];
        local.push_back(encrypt(pk, z));
    }
    if (!receiver) {
        net.send(peer, pack_ciphers(local));
        return {};
    }
    auto other = unpack_ciphers(net.recv(peer), c.bins);
    for (std::size_t i = 0; i < c.bins; ++i)
        local[i] = add(local[i], other[i]);
    return local;
}
void esc_boundary_test(const Config &original) {
    Config c = original;
    c.parties = 2;
    c.bins = 16;
    Network net(c);
    auto p = he_parameters(c).plain_modulus().value();
    std::vector<std::uint64_t> u = {0, 0,     1,     p - 1, p - 1, 1,  p / 2, p / 2 + 1,
                                    2, p - 2, p - 2, p - 1, 42,    73, p / 2, p - 100};
    std::vector<std::uint64_t> v = {0,     p - 1, p - 1, 1, p - 1, 0,      p / 2,     p / 2 + 1,
                                    p - 2, 2,     1,     0, 9,     p - 73, p / 2 + 2, 100};
    auto sk = Scalar::random();
    Point pk = Point::generator(sk);
    std::vector<Cipher> ct;
    if (c.party == 0) {
        net.send(1, pk.encode());
        ct = esc_convert(net, 1, c, p, v, pk);
        for (std::size_t i = 0; i < c.bins; ++i) {
            auto decoded = combine(ct[i], {partial_decrypt(sk, ct[i])});
            require(decoded == Point::generator(Scalar((u[i] + v[i]) % p)),
                    "ESC boundary test failed at " + std::to_string(i));
        }
    } else {
        pk = Point::decode(net.recv(0));
        esc_convert(net, 0, c, p, u, pk);
    }
    net.flush();
    std::ofstream f(c.report);
    f << "{\"status\":\"passed\",\"mode\":\"ESC boundary test only, known inputs\",\"party\":"
      << c.party << ",\"cases\":16,\"plain_modulus\":" << p << "}\n";
}
} // namespace mpwsi
