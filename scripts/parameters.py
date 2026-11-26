"""Choose public bucket counts from public set-size bounds, never occupancies."""
import math


def choose_bins(small, large, parties, capacity=64):
    if small < 0 or large < 0 or parties < 2 or not 1 <= capacity <= 128:
        raise ValueError("invalid public bucket sizing inputs")
    bins = 8
    # Same 1.6 cuckoo load factor as MinBucket, rounded to a power of two.
    while bins < math.ceil(1.6 * small):
        bins *= 2
    # For a fixed bin, each distinct item hits it with probability at most 3/m.
    # Chernoff + union bound across all bins/senders bounds overflow by 2^-40.
    # Actual overflows still abort in simple_hash; no item is ever dropped.
    k = capacity + 1
    while bins <= 1000000:
        mean = 3 * large / bins
        if not mean:
            return bins
        log_bound = math.log((parties - 1) * bins) + k - mean + k * math.log(mean / k)
        if mean < k and log_bound <= -40 * math.log(2):
            return bins
        bins *= 2
    raise ValueError("public size bounds need more than 1000000 bins; increase capacity")
