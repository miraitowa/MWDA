#pragma once
#include "common.h"
namespace mpwsi {
struct CuckooTable {
    Bytes seed;
    std::vector<std::optional<std::size_t>> records;
};
std::vector<std::size_t> hash_locations(const Bytes &seed, const std::string &id, std::size_t bins);
CuckooTable cuckoo_hash(const std::vector<Record> &records, std::size_t bins);
std::vector<std::vector<std::size_t>> simple_hash(const std::vector<Record> &records,
                                                  const Bytes &seed, std::size_t bins,
                                                  std::size_t capacity);
Bytes encode_identifier(const std::string &id);
std::vector<Bytes> query_identifiers(const CuckooTable &, const std::vector<Record> &);
} // namespace mpwsi
