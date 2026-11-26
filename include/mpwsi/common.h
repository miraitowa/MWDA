#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <coproto/Socket/AsioSocket.h>

namespace mpwsi {
using Bytes = std::vector<std::uint8_t>;
using Clock = std::chrono::steady_clock;
void require(bool ok, const std::string &message);
Bytes random_bytes(std::size_t n);
std::uint64_t random_below(std::uint64_t n);
std::string hex(const Bytes &data);
Bytes sha256(const Bytes &data);
std::string json_quote(const std::string &s);
double seconds(Clock::time_point t);
struct Writer {
    Bytes data;
    void u64(std::uint64_t v);
    void raw(const std::uint8_t *p, std::size_t n);
    void bytes(const Bytes &v);
    void str(const std::string &s);
};
struct Reader {
    const Bytes &data;
    std::size_t pos = 0;
    explicit Reader(const Bytes &v) : data(v) {}
    std::uint64_t u64();
    Bytes raw(std::size_t n);
    Bytes bytes(std::size_t limit = 512ULL * 1024 * 1024);
    std::string str(std::size_t limit = 1024 * 1024);
    void done() const;
};
struct Config {
    unsigned party = 0, parties = 3, threads = 1;
    unsigned base_port = 23400, timeout = 300;
    std::size_t bins = 0, capacity = 16, poly_degree = 16384;
    unsigned plain_bits = 50;
    std::uint64_t max_weight = 100, threshold = 150;
    std::string input, output, report;
    std::vector<std::string> hosts;
};
struct Record {
    std::string id;
    std::uint64_t weight;
    std::string features;
};
std::vector<Record> read_records(const std::string &path, std::uint64_t max_weight);
void write_aligned(const std::string &path, const std::vector<Record> &records,
                   const std::vector<std::string> &ids);
class Network {
    Config config_;
    std::vector<std::unique_ptr<coproto::Socket>> peers_;
    std::uint64_t sci_bytes_ = 0;

  public:
    explicit Network(const Config &config);
    coproto::Socket &socket(unsigned peer);
    void send(unsigned peer, const Bytes &data);
    Bytes recv(unsigned peer);
    void broadcast(const Bytes &data);
    void flush();
    void add_sci_bytes(std::uint64_t n) {
        sci_bytes_ += n;
    }
    std::uint64_t sci_bytes() const {
        return sci_bytes_;
    }
    std::uint64_t sent() const;
    std::uint64_t received() const;
};
struct Phase {
    std::string name;
    double wall_seconds;
    std::uint64_t sent_bytes, received_bytes, sci_bytes;
};
class Metrics {
    Network &network_;
    Clock::time_point last_;
    std::uint64_t sent_ = 0, received_ = 0, sci_ = 0;

  public:
    std::vector<Phase> phases;
    explicit Metrics(Network &n);
    void mark(const std::string &name);
    void write(const Config &config, std::uint64_t p, std::size_t output_count) const;
};
} // namespace mpwsi
