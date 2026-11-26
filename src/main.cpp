#include "mpwsi/protocol.h"
#include "mpwsi/esc.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <limits>
#include <omp.h>

int main(int argc, char **argv) {
    using namespace mpwsi;
    try {
        Config c;
        bool esc_test = false;
        for (int i = 1; i < argc; ++i) {
            std::string k = argv[i];
            if (k == "--help") {
                std::cout << "mpwsi_party --party N --parties T --input partyN.tsv --output "
                             "aligned.tsv --report metrics.json\n"
                          << "[--threshold 150 --max-weight 100 --bins 0 --capacity 16 "
                             "--plain-bits 50 --poly-degree 16384]\n"
                          << "[--base-port 23400 --hosts 127.0.0.1,... --threads 1 --timeout 300]\n"
                          << "--esc-test runs only a two-party known-input ESC boundary test.\n";
                return 0;
            }
            if (k == "--esc-test") {
                esc_test = true;
                continue;
            }
            require(i + 1 < argc, "missing value for " + k);
            std::string v = argv[++i];
            if (k == "--input")
                c.input = v;
            else if (k == "--output")
                c.output = v;
            else if (k == "--report")
                c.report = v;
            else if (k == "--hosts") {
                std::stringstream s(v);
                std::string h;
                while (std::getline(s, h, ','))
                    c.hosts.push_back(h);
            } else {
                require(!v.empty() && v.find_first_not_of("0123456789") == std::string::npos,
                        "invalid unsigned number for " + k);
                auto n = std::stoull(v);
                if (k != "--threshold" && k != "--max-weight")
                    require(n <= std::numeric_limits<unsigned>::max(), "numeric option too large");
                if (k == "--party")
                    c.party = n;
                else if (k == "--parties")
                    c.parties = n;
                else if (k == "--threshold")
                    c.threshold = n;
                else if (k == "--max-weight")
                    c.max_weight = n;
                else if (k == "--bins")
                    c.bins = n;
                else if (k == "--capacity")
                    c.capacity = n;
                else if (k == "--plain-bits")
                    c.plain_bits = n;
                else if (k == "--poly-degree")
                    c.poly_degree = n;
                else if (k == "--base-port")
                    c.base_port = n;
                else if (k == "--threads")
                    c.threads = n;
                else if (k == "--timeout")
                    c.timeout = n;
                else
                    throw std::runtime_error("unknown option: " + k);
            }
        }
        require(c.parties >= 2 && c.parties <= 16 && c.party < c.parties, "invalid party count/id");
        require(c.base_port >= 1024 && c.base_port <= 61000, "base-port outside supported range");
        require(c.capacity >= 1 && c.capacity <= 128, "capacity must be in [1,128]");
        require(c.bins == 0 || (c.bins >= 8 && c.bins <= 1000000),
                "bins must be 0 (automatic) or in [8,1000000]");
        require(c.plain_bits >= 20 && c.plain_bits <= 60, "plain-bits must be in [20,60]");
        require(c.poly_degree == 16384 || c.poly_degree == 32768,
                "poly-degree must be 16384 or 32768");
        require(c.threads == 1, "this reproducible reference implementation supports --threads 1");
        require(c.max_weight <= 100000000 / c.parties, "public valid weight domain exceeds 1e8");
        require(c.timeout >= 1 && c.timeout <= 86400,
                "timeout must be between 1 and 86400 seconds");
        require(!c.report.empty(), "--report is required");
        if (c.hosts.empty())
            c.hosts.assign(c.parties, "127.0.0.1");
        alarm(c.timeout);
        omp_set_num_threads(1);
        if (esc_test) {
            require(c.parties == 2, "ESC test needs exactly two parties");
            esc_boundary_test(c);
        } else {
            require(!c.input.empty() && !c.output.empty(), "--input and --output are required");
            run_protocol(c);
        }
        alarm(0);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "MPWSI ERROR: " << e.what() << '\n';
        return 1;
    }
}
