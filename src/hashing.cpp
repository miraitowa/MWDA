#include "mpwsi/hashing.h"
#include <algorithm>
#include <deque>

namespace mpwsi {
std::vector<std::size_t> hash_locations(const Bytes &seed, const std::string &id,
                                        std::size_t bins) {
    require(bins >= 3, "hash table requires at least three bins");
    std::vector<std::size_t> out;
    for (unsigned k = 0; k < 3; ++k) {
        Writer w;
        w.str("MPWSI/hash/v1");
        w.bytes(seed);
        w.u64(k);
        w.str(id);
        auto h = sha256(w.data);
        std::uint64_t x = 0;
        for (unsigned j = 0; j < 8; ++j)
            x |= std::uint64_t(h[j]) << (8 * j);
        auto b = x % bins;
        if (std::find(out.begin(), out.end(), b) == out.end())
            out.push_back(b);
    }
    return out;
}
CuckooTable cuckoo_hash(const std::vector<Record> &records, std::size_t bins) {
    require(records.size() <= bins, "more coordinator records than bins");
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        CuckooTable t{random_bytes(32), std::vector<std::optional<std::size_t>>(bins)};
        bool success = true;
        for (std::size_t item = 0; item < records.size(); ++item) {
            std::vector<std::ptrdiff_t> parent(bins, -1);
            std::deque<std::size_t> q;
            for (auto b : hash_locations(t.seed, records[item].id, bins)) {
                parent[b] = -2;
                q.push_back(b);
            }
            std::optional<std::size_t> vacant;
            while (!q.empty()) {
                auto b = q.front();
                q.pop_front();
                if (!t.records[b]) {
                    vacant = b;
                    break;
                }
                for (auto next : hash_locations(t.seed, records[*t.records[b]].id, bins))
                    if (parent[next] == -1) {
                        parent[next] = b;
                        q.push_back(next);
                    }
            }
            if (!vacant) {
                success = false;
                break;
            }
            auto b = *vacant;
            while (parent[b] != -2) {
                auto prev = static_cast<std::size_t>(parent[b]);
                t.records[b] = t.records[prev];
                b = prev;
            }
            t.records[b] = item;
        }
        if (success)
            return t;
    }
    throw std::runtime_error("cuckoo hashing failed after 32 fresh seeds; increase --bins");
}
std::vector<std::vector<std::size_t>> simple_hash(const std::vector<Record> &records,
                                                  const Bytes &seed, std::size_t bins,
                                                  std::size_t capacity) {
    std::vector<std::vector<std::size_t>> t(bins);
    for (std::size_t j = 0; j < records.size(); ++j)
        for (auto b : hash_locations(seed, records[j].id, bins)) {
            t[b].push_back(j);
            require(t[b].size() <= capacity,
                    "simple hash bin overflow; increase public --capacity or --bins");
        }
    return t;
}
Bytes encode_identifier(const std::string &id) {
    Writer w;
    w.str("MPWSI/real-id/v1");
    w.str(id);
    return w.data;
}
std::vector<Bytes> query_identifiers(const CuckooTable &t, const std::vector<Record> &records) {
    std::vector<Bytes> out;
    out.reserve(t.records.size());
    for (std::size_t b = 0; b < t.records.size(); ++b) {
        if (t.records[b])
            out.push_back(encode_identifier(records[*t.records[b]].id));
        else {
            Writer w;
            w.str("MPWSI/dummy/v1");
            w.bytes(random_bytes(32));
            w.u64(b);
            out.push_back(w.data);
        }
    }
    return out;
}
} // namespace mpwsi
