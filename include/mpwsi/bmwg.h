#pragma once
#include "common.h"
#include <seal/seal.h>
namespace mpwsi {
seal::EncryptionParameters he_parameters(const Config &);
struct MembershipShares {
    std::vector<std::uint64_t> label, weight;
};
struct BmwgReceiverSession {
    std::shared_ptr<seal::SEALContext> context;
    seal::SecretKey secret_key;
};
// Split query submission from collection to overlap independent senders.
// All protocol computation in each party remains single-threaded.
BmwgReceiverSession bmwg_receiver_begin(Network &, unsigned peer, const Config &,
                                       const std::vector<Bytes> &query);
MembershipShares bmwg_receiver_finish(Network &, unsigned peer, const Config &,
                                     const BmwgReceiverSession &);
// Receiver returns (t,v); sender returns (s,u). No labels or weight shares
// are opened by either function.
MembershipShares bmwg_receiver(Network &, unsigned peer, const Config &,
                               const std::vector<Bytes> &query);
MembershipShares bmwg_sender(Network &, unsigned peer, const Config &, const std::vector<Record> &,
                             const std::vector<std::vector<std::size_t>> &bins);
std::uint64_t field_hash(const std::array<unsigned char, 32> &, std::uint64_t p);
} // namespace mpwsi
