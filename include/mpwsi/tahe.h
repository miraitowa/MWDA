#pragma once
#include "common.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <unordered_map>

namespace mpwsi {
// T-of-T threshold exponential ElGamal in the prime-order NIST P-256 group.
// Scalars are always canonical residues modulo the group order q.
const EC_GROUP *group();
const BIGNUM *order();
BN_CTX *bn_context();
class Scalar {
    BIGNUM *v_;

  public:
    explicit Scalar(std::uint64_t value = 0);
    Scalar(const Scalar &);
    Scalar(Scalar &&) noexcept;
    Scalar &operator=(Scalar other) noexcept;
    ~Scalar();
    static Scalar random();
    static Scalar decode(const Bytes &b);
    Bytes encode() const;
    const BIGNUM *get() const {
        return v_;
    }
    Scalar operator+(const Scalar &) const;
    Scalar operator-(const Scalar &) const;
    Scalar operator*(const Scalar &) const;
    bool operator==(const Scalar &) const;
};
class Point {
    EC_POINT *p_;

  public:
    Point();
    Point(const Point &);
    Point(Point &&) noexcept;
    Point &operator=(Point other) noexcept;
    ~Point();
    static Point generator(const Scalar &);
    static Point decode(const Bytes &);
    Bytes encode() const;
    Point operator+(const Point &) const;
    Point operator-(const Point &) const;
    Point operator*(const Scalar &) const;
    bool operator==(const Point &) const;
    bool infinity() const;
};
struct Cipher {
    Point r, s;
};
Cipher encrypt(const Point &pk, const Scalar &message);
Cipher add(const Cipher &, const Cipher &);
Cipher subtract(const Cipher &, const Cipher &);
Cipher scale(const Cipher &, const Scalar &);
Cipher rerandomize(const Point &, const Cipher &);
Point partial_decrypt(const Scalar &, const Cipher &);
Point combine(const Cipher &, const std::vector<Point> &);
void put(Writer &, const Point &);
void put(Writer &, const Cipher &);
Point get_point(Reader &);
Cipher get_cipher(Reader &);
Bytes pack_ciphers(const std::vector<Cipher> &);
std::vector<Cipher> unpack_ciphers(const Bytes &, std::size_t expected);
Bytes pack_points(const std::vector<Point> &);
std::vector<Point> unpack_points(const Bytes &, std::size_t expected);
class BoundedDlog {
    std::uint64_t bound_, step_;
    Point giant_step_;
    std::unordered_map<std::string, std::uint64_t> baby_;

  public:
    explicit BoundedDlog(std::uint64_t bound);
    std::optional<std::uint64_t> decode(Point p) const;
};
} // namespace mpwsi
