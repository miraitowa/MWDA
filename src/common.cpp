#include "mpwsi/common.h"
#include "mpwsi/bmwg.h"
#include "mpwsi/bfv_polynomial.h"
#include <algorithm>
#include <climits>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace mpwsi {
void require(bool ok, const std::string &m) {
    if (!ok)
        throw std::runtime_error(m);
}
Bytes random_bytes(std::size_t n) {
    require(n <= INT_MAX, "random request too large");
    Bytes b(n);
    require(RAND_bytes(b.data(), static_cast<int>(n)) == 1, "RAND_bytes failed");
    return b;
}
std::uint64_t random_below(std::uint64_t n) {
    require(n > 0, "empty random range");
    const auto threshold = (std::uint64_t(0) - n) % n;
    for (;;) {
        auto b = random_bytes(8);
        std::uint64_t r;
        std::memcpy(&r, b.data(), 8);
        if (r >= threshold)
            return r % n;
    }
}
std::string hex(const Bytes &b) {
    static const char *h = "0123456789abcdef";
    std::string s;
    for (auto x : b) {
        s += h[x >> 4];
        s += h[x & 15];
    }
    return s;
}
Bytes sha256(const Bytes &b) {
    Bytes h(SHA256_DIGEST_LENGTH);
    SHA256(b.data(), b.size(), h.data());
    return h;
}
std::string json_quote(const std::string &s) {
    static const char *h = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (c < 32) {
            out += "\\u00";
            out += h[c >> 4];
            out += h[c & 15];
        } else
            out += c;
    }
    return out + '"';
}
double seconds(Clock::time_point t) {
    return std::chrono::duration<double>(Clock::now() - t).count();
}
void Writer::u64(std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i)
        data.push_back((v >> (8 * i)) & 255);
}
void Writer::raw(const std::uint8_t *p, std::size_t n) {
    if (n)
        data.insert(data.end(), p, p + n);
}
void Writer::bytes(const Bytes &v) {
    u64(v.size());
    raw(v.data(), v.size());
}
void Writer::str(const std::string &s) {
    u64(s.size());
    raw(reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
}
std::uint64_t Reader::u64() {
    require(data.size() - pos >= 8, "truncated integer");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i)
        v |= std::uint64_t(data[pos++]) << (8 * i);
    return v;
}
Bytes Reader::raw(std::size_t n) {
    require(n <= data.size() - pos, "truncated message");
    Bytes b(data.begin() + pos, data.begin() + pos + n);
    pos += n;
    return b;
}
Bytes Reader::bytes(std::size_t limit) {
    auto n = u64();
    require(n <= limit, "message field exceeds limit");
    return raw(n);
}
std::string Reader::str(std::size_t limit) {
    auto b = bytes(limit);
    return {b.begin(), b.end()};
}
void Reader::done() const {
    require(pos == data.size(), "unexpected trailing data");
}

std::vector<Record> read_records(const std::string &path, std::uint64_t max_weight) {
    std::ifstream f(path);
    require(bool(f), "cannot open input: " + path);
    std::string line;
    require(bool(std::getline(f, line)) &&
                (line == "id\tweight\tfeatures" || line == "id\tweight\tfeatures\r"),
            "TSV header must be id, weight, features");
    std::vector<Record> r;
    std::set<std::string> seen;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        auto a = line.find('\t'), b = a == std::string::npos ? a : line.find('\t', a + 1);
        require(a != std::string::npos && b != std::string::npos, "invalid TSV row");
        auto id = line.substr(0, a), w = line.substr(a + 1, b - a - 1);
        require(!id.empty() && id.size() <= 4096 && id.find('\0') == std::string::npos,
                "invalid identifier");
        require(seen.insert(id).second, "duplicate identifier: " + id);
        require(!w.empty() && std::all_of(w.begin(), w.end(),
                                          [](unsigned char c) { return c >= '0' && c <= '9'; }),
                "weight must be an unsigned decimal integer");
        auto value = std::stoull(w);
        require(value <= max_weight, "weight exceeds public max-weight");
        auto feature = line.substr(b + 1);
        require(feature.find('\t') == std::string::npos, "feature must not contain Tab");
        r.push_back({id, value, feature});
    }
    return r;
}
void write_aligned(const std::string &path, const std::vector<Record> &records,
                   const std::vector<std::string> &ids) {
    std::map<std::string, const Record *> lookup;
    for (auto &r : records)
        lookup.emplace(r.id, &r);
    std::ofstream f(path);
    require(bool(f), "cannot write output: " + path);
    f << "id\tfeatures\n";
    for (auto &id : ids) {
        auto it = lookup.find(id);
        require(it != lookup.end(), "selected identifier absent from local input");
        f << id << '\t' << it->second->features << '\n';
    }
    require(bool(f), "output write failed");
}
Network::Network(const Config &c) : config_(c), peers_(c.parties) {
    require(c.hosts.size() == c.parties, "one host per party is required");
    for (unsigned p = 0; p < c.parties; ++p)
        if (p != c.party) {
            unsigned lo = std::min(p, c.party), hi = std::max(p, c.party);
            auto address = c.hosts[lo] + ":" + std::to_string(c.base_port + lo * c.parties + hi);
            peers_[p] =
                std::make_unique<coproto::Socket>(coproto::asioConnect(address, c.party == lo));
        }
}
coproto::Socket &Network::socket(unsigned p) {
    require(p < peers_.size() && peers_[p] != nullptr, "invalid peer");
    return *peers_[p];
}
void Network::send(unsigned p, const Bytes &data) {
    Writer w;
    w.u64(data.size());
    coproto::sync_wait(socket(p).send(coproto::copy(w.data)));
    if (!data.empty())
        coproto::sync_wait(socket(p).send(coproto::copy(data)));
}
Bytes Network::recv(unsigned p) {
    Bytes header(8);
    coproto::sync_wait(socket(p).recv(header));
    Reader r(header);
    auto n = r.u64();
    require(n <= 512ULL * 1024 * 1024, "network frame exceeds 512 MiB");
    Bytes b(n);
    if (n)
        coproto::sync_wait(socket(p).recv(b));
    return b;
}
void Network::broadcast(const Bytes &b) {
    for (unsigned p = 0; p < config_.parties; ++p)
        if (p != config_.party)
            send(p, b);
}
void Network::flush() {
    // send(copy(...)) may complete while the underlying transport is pending.
    // Drain every socket before a successful party exits and destroys it.
    for (auto &peer : peers_)
        if (peer)
            coproto::sync_wait(peer->flush());
}
std::uint64_t Network::sent() const {
    std::uint64_t n = 0;
    for (auto &p : peers_)
        if (p)
            n += p->bytesSent();
    return n;
}
std::uint64_t Network::received() const {
    std::uint64_t n = 0;
    for (auto &p : peers_)
        if (p)
            n += p->bytesReceived();
    return n;
}
Metrics::Metrics(Network &n) : network_(n), last_(Clock::now()) {}
void Metrics::mark(const std::string &name) {
    auto s = network_.sent(), r = network_.received(), z = network_.sci_bytes();
    phases.push_back({name, seconds(last_), s - sent_, r - received_, z - sci_});
    sent_ = s;
    received_ = r;
    sci_ = z;
    last_ = Clock::now();
    std::cerr << name << " complete\n";
}
void Metrics::write(const Config &c, std::uint64_t p, std::size_t count) const {
    std::ofstream f(c.report);
    require(bool(f), "cannot write metrics");
    f << "{\n\"status\":\"passed\",\"party\":" << c.party << ",\"parties\":" << c.parties
      << ",\"bins\":" << c.bins << ",\"bin_capacity\":" << c.capacity << ",\"plain_modulus\":" << p
      << ",\"poly_modulus_degree\":" << c.poly_degree << ",\"threads\":" << c.threads
      << ",\"threshold\":" << c.threshold << ",\"max_weight\":" << c.max_weight
      << ",\"selected_count\":" << count
      << ",\"bmwg_evaluator\":\"Paterson-Stockmeyer with seeded sparse query powers\""
      << ",\"bfv_query_powers\":[";
    auto query_powers = polynomial_query_powers(c.capacity);
    for (std::size_t i = 0; i < query_powers.size(); ++i)
        f << (i ? "," : "") << query_powers[i];
    f << "],\"bfv_coeff_modulus_bits\":[";
    auto params = he_parameters(c);
    for (std::size_t i = 0; i < params.coeff_modulus().size(); ++i)
        f << (i ? "," : "") << params.coeff_modulus()[i].bit_count();
    f << "],\"bfv_security_level_bits\":128"
      << ",\"security_status\":\"research prototype; BFV circuit privacy unresolved\",\"phases\":[";
    for (std::size_t i = 0; i < phases.size(); ++i) {
        if (i)
            f << ',';
        auto &s = phases[i];
        f << "{\"name\":" << json_quote(s.name) << ",\"wall_seconds\":" << s.wall_seconds
          << ",\"sent_bytes\":" << s.sent_bytes << ",\"received_bytes\":" << s.received_bytes
          << ",\"sci_sent_plus_received_bytes\":" << s.sci_bytes << '}';
    }
    f << "],\"sent_bytes\":" << network_.sent() << ",\"received_bytes\":" << network_.received()
      << ",\"sci_sent_plus_received_bytes\":" << network_.sci_bytes() << "}\n";
}
} // namespace mpwsi
