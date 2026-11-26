#include "mpwsi/tahe.h"
#include <algorithm>
#include <cmath>
#include <openssl/obj_mac.h>

namespace mpwsi {
const EC_GROUP *group() {
    static auto g = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    require(bool(g), "P-256 unavailable");
    return g.get();
}
BN_CTX *bn_context() {
    thread_local auto c =
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>(BN_CTX_new(), BN_CTX_free);
    require(bool(c), "BN context allocation failed");
    return c.get();
}
const BIGNUM *order() {
    return EC_GROUP_get0_order(group());
}
Scalar::Scalar(std::uint64_t n) : v_(BN_new()) {
    require(v_ && BN_set_word(v_, n) == 1, "scalar allocation failed");
}
Scalar::Scalar(const Scalar &b) : v_(BN_dup(b.v_)) {
    require(v_ != nullptr, "scalar allocation failed");
}
Scalar::Scalar(Scalar &&b) noexcept : v_(b.v_) {
    b.v_ = nullptr;
}
Scalar &Scalar::operator=(Scalar b) noexcept {
    std::swap(v_, b.v_);
    return *this;
}
Scalar::~Scalar() {
    BN_clear_free(v_);
}
Scalar Scalar::random() {
    Scalar a;
    require(BN_priv_rand_range(a.v_, order()) == 1, "scalar randomness failed");
    return a;
}
Scalar Scalar::decode(const Bytes &b) {
    require(b.size() == 32, "scalar must be 32 bytes");
    Scalar a;
    require(BN_bin2bn(b.data(), 32, a.v_) != nullptr && BN_cmp(a.v_, order()) < 0,
            "noncanonical scalar");
    return a;
}
Bytes Scalar::encode() const {
    Bytes b(32);
    require(BN_bn2binpad(v_, b.data(), 32) == 32, "scalar encoding failed");
    return b;
}
Scalar Scalar::operator+(const Scalar &b) const {
    Scalar c;
    require(BN_mod_add(c.v_, v_, b.v_, order(), bn_context()) == 1, "scalar add failed");
    return c;
}
Scalar Scalar::operator-(const Scalar &b) const {
    Scalar c;
    require(BN_mod_sub(c.v_, v_, b.v_, order(), bn_context()) == 1, "scalar subtract failed");
    return c;
}
Scalar Scalar::operator*(const Scalar &b) const {
    Scalar c;
    require(BN_mod_mul(c.v_, v_, b.v_, order(), bn_context()) == 1, "scalar multiply failed");
    return c;
}
bool Scalar::operator==(const Scalar &b) const {
    return BN_cmp(v_, b.v_) == 0;
}
Point::Point() : p_(EC_POINT_new(group())) {
    require(p_ != nullptr && EC_POINT_set_to_infinity(group(), p_) == 1, "point allocation failed");
}
Point::Point(const Point &b) : p_(EC_POINT_dup(b.p_, group())) {
    require(p_ != nullptr, "point allocation failed");
}
Point::Point(Point &&b) noexcept : p_(b.p_) {
    b.p_ = nullptr;
}
Point &Point::operator=(Point b) noexcept {
    std::swap(p_, b.p_);
    return *this;
}
Point::~Point() {
    EC_POINT_clear_free(p_);
}
Point Point::generator(const Scalar &s) {
    Point p;
    require(EC_POINT_mul(group(), p.p_, s.get(), nullptr, nullptr, bn_context()) == 1,
            "generator multiply failed");
    return p;
}
Bytes Point::encode() const {
    Bytes b(33);
    if (!infinity())
        require(EC_POINT_point2oct(group(), p_, POINT_CONVERSION_COMPRESSED, b.data(), b.size(),
                                   bn_context()) == 33,
                "point encoding failed");
    return b;
}
Point Point::decode(const Bytes &b) {
    require(b.size() == 33, "point must be 33 bytes");
    Point p;
    if (std::all_of(b.begin(), b.end(), [](auto x) { return x == 0; }))
        return p;
    require((b[0] == 2 || b[0] == 3) &&
                EC_POINT_oct2point(group(), p.p_, b.data(), b.size(), bn_context()) == 1 &&
                EC_POINT_is_on_curve(group(), p.p_, bn_context()) == 1,
            "invalid curve point");
    return p;
}
Point Point::operator+(const Point &b) const {
    Point c;
    require(EC_POINT_add(group(), c.p_, p_, b.p_, bn_context()) == 1, "point add failed");
    return c;
}
Point Point::operator-(const Point &b) const {
    Point n(b);
    require(EC_POINT_invert(group(), n.p_, bn_context()) == 1, "point negation failed");
    return *this + n;
}
Point Point::operator*(const Scalar &s) const {
    Point c;
    require(EC_POINT_mul(group(), c.p_, nullptr, p_, s.get(), bn_context()) == 1,
            "point scalar multiply failed");
    return c;
}
bool Point::operator==(const Point &b) const {
    return EC_POINT_cmp(group(), p_, b.p_, bn_context()) == 0;
}
bool Point::infinity() const {
    return EC_POINT_is_at_infinity(group(), p_) == 1;
}
Cipher encrypt(const Point &pk, const Scalar &m) {
    auto r = Scalar::random();
    return {Point::generator(r), pk * r + Point::generator(m)};
}
Cipher add(const Cipher &a, const Cipher &b) {
    return {a.r + b.r, a.s + b.s};
}
Cipher subtract(const Cipher &a, const Cipher &b) {
    return {a.r - b.r, a.s - b.s};
}
Cipher scale(const Cipher &a, const Scalar &b) {
    return {a.r * b, a.s * b};
}
Cipher rerandomize(const Point &pk, const Cipher &a) {
    return add(a, encrypt(pk, Scalar()));
}
Point partial_decrypt(const Scalar &sk, const Cipher &c) {
    return c.r * sk;
}
Point combine(const Cipher &c, const std::vector<Point> &shares) {
    Point m = c.s;
    for (auto &s : shares)
        m = m - s;
    return m;
}
void put(Writer &w, const Point &p) {
    auto b = p.encode();
    w.raw(b.data(), b.size());
}
void put(Writer &w, const Cipher &c) {
    put(w, c.r);
    put(w, c.s);
}
Point get_point(Reader &r) {
    return Point::decode(r.raw(33));
}
Cipher get_cipher(Reader &r) {
    auto a = get_point(r);
    auto b = get_point(r);
    return {a, b};
}
Bytes pack_ciphers(const std::vector<Cipher> &v) {
    Writer w;
    w.u64(v.size());
    for (auto &c : v)
        put(w, c);
    return w.data;
}
std::vector<Cipher> unpack_ciphers(const Bytes &b, std::size_t n) {
    Reader r(b);
    require(r.u64() == n, "unexpected ciphertext count");
    std::vector<Cipher> v;
    v.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
        v.push_back(get_cipher(r));
    r.done();
    return v;
}
Bytes pack_points(const std::vector<Point> &v) {
    Writer w;
    w.u64(v.size());
    for (auto &p : v)
        put(w, p);
    return w.data;
}
std::vector<Point> unpack_points(const Bytes &b, std::size_t n) {
    Reader r(b);
    require(r.u64() == n, "unexpected point count");
    std::vector<Point> v;
    v.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
        v.push_back(get_point(r));
    r.done();
    return v;
}
BoundedDlog::BoundedDlog(std::uint64_t bound)
    : bound_(bound), step_(static_cast<std::uint64_t>(std::sqrt(bound)) + 1),
      giant_step_(Point::generator(Scalar(step_))) {
    require(bound <= 100000000, "valid-domain bound exceeds supported decoding limit (1e8)");
    Point p, g = Point::generator(Scalar(1));
    for (std::uint64_t i = 0; i < step_; ++i) {
        baby_.emplace(hex(p.encode()), i);
        p = p + g;
    }
}
std::optional<std::uint64_t> BoundedDlog::decode(Point p) const {
    for (std::uint64_t j = 0; j <= bound_ / step_; ++j) {
        auto it = baby_.find(hex(p.encode()));
        if (it != baby_.end()) {
            auto n = j * step_ + it->second;
            if (n <= bound_)
                return n;
        }
        p = p - giant_step_;
    }
    return std::nullopt;
}
} // namespace mpwsi
