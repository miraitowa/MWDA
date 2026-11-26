#include "mpwsi/protocol.h"
#include "mpwsi/bmwg.h"
#include "mpwsi/esc.h"
#include "mpwsi/hashing.h"
#include "mpwsi/tahe.h"
#include <algorithm>
#include <iostream>
#include <set>

namespace mpwsi {
namespace {
std::vector<Point> shares_for(const Scalar &sk, const std::vector<Cipher> &c) {
    std::vector<Point> r;
    r.reserve(c.size());
    for (auto &x : c)
        r.push_back(partial_decrypt(sk, x));
    return r;
}
std::vector<Point> threshold_open(Network &net, const Config &c, const Scalar &sk,
                                  const std::vector<Cipher> &ct) {
    if (c.party != 0) {
        auto b = net.recv(0);
        Reader count(b);
        auto n = count.u64();
        require(n <= c.bins, "decryption request too large");
        auto incoming = unpack_ciphers(b, n);
        net.send(0, pack_points(shares_for(sk, incoming)));
        return {};
    }
    net.broadcast(pack_ciphers(ct));
    auto own = shares_for(sk, ct);
    std::vector<Point> plain;
    plain.reserve(ct.size());
    for (std::size_t i = 0; i < ct.size(); ++i)
        plain.push_back(ct[i].s - own[i]);
    for (unsigned k = 1; k < c.parties; ++k) {
        auto other = unpack_points(net.recv(k), ct.size());
        for (std::size_t i = 0; i < ct.size(); ++i)
            plain[i] = plain[i] - other[i];
    }
    return plain;
}
void shuffle(std::vector<Cipher> &pairs, const Point &pk) {
    require(pairs.size() % 2 == 0, "invalid shuffle pair count");
    for (auto &ct : pairs)
        ct = rerandomize(pk, ct);
    // Fisher-Yates, using unbiased cryptographic draws, same permutation on
    // each (weight,index) pair. No permutation/coins are logged or shared.
    for (std::size_t i = pairs.size() / 2; i > 1; --i) {
        auto j = random_below(i);
        std::swap(pairs[2 * (i - 1)], pairs[2 * j]);
        std::swap(pairs[2 * (i - 1) + 1], pairs[2 * j + 1]);
    }
}
} // namespace
void run_protocol(Config c) {
    auto records = read_records(c.input, c.max_weight);
    require(records.size() <= 100000000, "input exceeds reference implementation size limit");
    Network net(c);
    Metrics metrics(net);
    CuckooTable table;
    Bytes seed;
    std::vector<std::vector<std::size_t>> sender_bins;
    // Public setup: parameters and one seed, never identifiers or weights.
    if (c.party == 0) {
        if (!c.bins) {
            c.bins = 8;
            while (c.bins < records.size() * 1.6)
                c.bins *= 2;
        }
        table = cuckoo_hash(records, c.bins);
        seed = table.seed;
        Writer setup;
        setup.str("MPWSI-v3-depth1");
        setup.u64(c.parties);
        setup.u64(c.bins);
        setup.u64(c.capacity);
        setup.u64(c.poly_degree);
        setup.u64(c.plain_bits);
        setup.u64(c.max_weight);
        setup.u64(c.threshold);
        setup.bytes(seed);
        net.broadcast(setup.data);
    } else {
        auto b = net.recv(0);
        Reader r(b);
        require(r.str() == "MPWSI-v3-depth1" && r.u64() == c.parties, "protocol/session mismatch");
        auto bins = r.u64();
        require(bins >= 8 && bins <= 1000000, "unsupported received bin count");
        require(!c.bins || c.bins == bins, "bin count mismatch");
        c.bins = bins;
        require(r.u64() == c.capacity && r.u64() == c.poly_degree && r.u64() == c.plain_bits &&
                    r.u64() == c.max_weight && r.u64() == c.threshold,
                "public parameter mismatch");
        seed = r.bytes(32);
        r.done();
        require(seed.size() == 32, "invalid hash seed");
        sender_bins = simple_hash(records, seed, c.bins, c.capacity);
    }
    require(c.bins >= 8 && c.bins <= 1000000, "unsupported bin count");
    auto p = he_parameters(c).plain_modulus().value();
    require(c.max_weight < p, "weights must be below p");
    metrics.mark("hashing_and_public_setup");
    // MPWSI step 1: additive independent key shares; no party learns sk.
    Scalar sk;
    do {
        sk = Scalar::random();
    } while (sk == Scalar());
    Point ownpk = Point::generator(sk), pk;
    if (c.party == 0) {
        std::vector<Point> public_shares{ownpk};
        for (unsigned k = 1; k < c.parties; ++k) {
            auto x = Point::decode(net.recv(k));
            require(!x.infinity(), "zero public key share");
            public_shares.push_back(x);
        }
        net.broadcast(pack_points(public_shares));
        for (auto &x : public_shares)
            pk = pk + x;
    } else {
        net.send(0, ownpk.encode());
        auto all = unpack_points(net.recv(0), c.parties);
        require(all[c.party] == ownpk, "own public key share changed");
        for (auto &x : all) {
            require(!x.infinity(), "zero public key share");
            pk = pk + x;
        }
    }
    require(!pk.infinity(), "aggregate public key is zero; restart key generation");
    metrics.mark("threshold_keygen");
    std::vector<MembershipShares> receiver_shares(c.parties);
    MembershipShares sender_share;
    std::vector<std::vector<Cipher>> encrypted_weights(c.parties);
    if (c.party == 0) {
        auto queries = query_identifiers(table, records);
        std::vector<BmwgReceiverSession> sessions(c.parties);
        for (unsigned k = 1; k < c.parties; ++k)
            sessions[k] = bmwg_receiver_begin(net, k, c, queries);
        metrics.mark("bmwg_query_submission");
        for (unsigned k = 1; k < c.parties; ++k)
            receiver_shares[k] = bmwg_receiver_finish(net, k, c, sessions[k]);
        metrics.mark("bmwg_response_collection");
        sessions.clear();
        for (unsigned k = 1; k < c.parties; ++k) {
            encrypted_weights[k] = esc_convert(net, k, c, p, receiver_shares[k].weight, pk);
            metrics.mark("esc_peer_" + std::to_string(k));
        }
    } else {
        sender_share = bmwg_sender(net, 0, c, records, sender_bins);
        metrics.mark("bmwg");
        esc_convert(net, 0, c, p, sender_share.weight, pk);
        metrics.mark("esc");
    }

    // CJWA: independent beta per party/bin, then independent alpha at ALL T
    // parties. It is not the unweighted MinBucket J-PEQT protocol.
    std::vector<Cipher> R(c.bins), joint(c.bins);
    if (c.party == 0) {
        for (unsigned k = 1; k < c.parties; ++k) {
            auto labels = unpack_ciphers(net.recv(k), c.bins);
            for (std::size_t i = 0; i < c.bins; ++i) {
                auto diff = subtract(labels[i], encrypt(pk, Scalar(receiver_shares[k].label[i])));
                R[i] = add(R[i], scale(diff, Scalar::random()));
            }
        }
        net.broadcast(pack_ciphers(R));
        for (std::size_t i = 0; i < c.bins; ++i) {
            auto own_weight = table.records[i] ? records[*table.records[i]].weight : 0;
            joint[i] = encrypt(pk, Scalar(own_weight));
            for (unsigned k = 1; k < c.parties; ++k)
                joint[i] = add(joint[i], encrypted_weights[k][i]);
            joint[i] = add(joint[i], rerandomize(pk, scale(R[i], Scalar::random())));
        }
        for (unsigned k = 1; k < c.parties; ++k) {
            auto masked = unpack_ciphers(net.recv(k), c.bins);
            for (std::size_t i = 0; i < c.bins; ++i)
                joint[i] = add(joint[i], masked[i]);
        }
        for (auto &ct : joint)
            ct = rerandomize(pk, ct);
    } else {
        std::vector<Cipher> labels;
        for (auto s : sender_share.label)
            labels.push_back(encrypt(pk, Scalar(s)));
        net.send(0, pack_ciphers(labels));
        R = unpack_ciphers(net.recv(0), c.bins);
        for (auto &ct : R)
            ct = rerandomize(pk, scale(ct, Scalar::random()));
        net.send(0, pack_ciphers(R));
    }
    metrics.mark("cjwa");
    std::vector<Cipher> pairs;
    if (c.party == 0) {
        pairs.reserve(2 * c.bins);
        for (std::size_t i = 0; i < c.bins; ++i) {
            pairs.push_back(joint[i]);
            pairs.push_back(encrypt(pk, Scalar(i)));
        }
    } else
        pairs = unpack_ciphers(net.recv(c.party - 1), 2 * c.bins);
    shuffle(pairs, pk);
    net.send(c.party + 1 < c.parties ? c.party + 1 : 0, pack_ciphers(pairs));
    if (c.party == 0)
        pairs = unpack_ciphers(net.recv(c.parties - 1), 2 * c.bins);
    metrics.mark("joint_pair_shuffle");
    std::vector<Cipher> weights;
    if (c.party == 0)
        for (std::size_t i = 0; i < c.bins; ++i)
            weights.push_back(pairs[2 * i]);
    auto weight_points = threshold_open(net, c, sk, weights);
    metrics.mark("threshold_weight_decryption");
    std::vector<Cipher> indices;
    if (c.party == 0) {
        BoundedDlog decoder(c.max_weight * c.parties);
        for (std::size_t i = 0; i < c.bins; ++i) {
            auto value = decoder.decode(weight_points[i]);
            if (value && *value >= c.threshold)
                indices.push_back(rerandomize(pk, pairs[2 * i + 1]));
        }
    }
    auto index_points = threshold_open(net, c, sk, indices);
    metrics.mark("predicate_and_selected_index_decryption");
    std::vector<std::string> selected;
    if (c.party == 0) {
        BoundedDlog decoder(c.bins - 1);
        std::set<std::size_t> used;
        for (auto &point : index_points) {
            auto index = decoder.decode(point);
            require(index && table.records[*index].has_value(),
                    "invalid/dummy selected index (hash collision or protocol failure)");
            require(used.insert(*index).second, "duplicate selected index");
            selected.push_back(records[*table.records[*index]].id);
        }
        std::sort(selected.begin(), selected.end());
        Writer w;
        w.u64(selected.size());
        for (auto &id : selected)
            w.str(id);
        net.broadcast(w.data);
    } else {
        auto b = net.recv(0);
        Reader r(b);
        auto n = r.u64();
        require(n <= c.bins, "invalid result length");
        for (std::size_t i = 0; i < n; ++i)
            selected.push_back(r.str(4096));
        r.done();
        require(std::is_sorted(selected.begin(), selected.end()) &&
                    std::adjacent_find(selected.begin(), selected.end()) == selected.end(),
                "output is not sorted/distinct");
    }
    write_aligned(c.output, records, selected);
    net.flush();
    metrics.mark("local_feature_alignment");
    metrics.write(c, p, selected.size());
    std::cout << "party " << c.party << ": selected " << selected.size() << " identifiers\n";
}
} // namespace mpwsi
