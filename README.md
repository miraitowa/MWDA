# MWDA

MWDA is a research implementation of multi-party weighted set intersection and local
feature alignment. Each participant runs a separate C++ process, reads its own
input, and keeps its feature payload local. Selected identifiers belong to the
intersection of all parties and have a total weight at least the public threshold.

The C++ namespace, include paths and executable retain the internal identifier
`mpwsi`; `mpwsi_party` is the participant entry point for MWDA.

## Layout

- `src/`, `include/mpwsi/`: protocol implementation and headers.
- `src/protocol.cpp`: protocol orchestration, joint aggregation, shuffling,
  threshold selection and index opening.
- `src/bmwg.cpp`, `src/bfv_polynomial.cpp`, `src/plain_polynomial.cpp`:
  bucketed weighted matching and polynomial evaluation.
- `src/esc.cpp`: secure comparison and Boolean-to-arithmetic conversion.
- `src/tahe.cpp`: threshold additive homomorphic encryption.
- `src/hashing.cpp`, `src/common.cpp`: hashing, communication and input/output.
- `src/main.cpp`: participant command-line entry point.
- `tests/`: native unit and boundary tests.
- `scripts/`: build, local correctness checks and public parameter selection.

## Dependencies

Use Linux x86-64, a CPU supporting AES-NI/AVX2, a C++20 compiler, CMake >= 3.16,
and Python 3. The CMake project requires OpenSSL, GMP, OpenMP, Microsoft SEAL
4.1, volePSI (including its coproto network dependency), Microsoft GSL and Kuku.

Two external source trees are also required:

- `MINBUCKET_ROOT`: a MinBucket-MPSI checkout containing the APSU/FourQ
  primitives at `uMCRG/MCRG/common`.
- `EZPC_ROOT`: an EzPC checkout containing `SCI/src`, used for comparison and OT.

These external components retain their upstream attribution and licenses.
Their source trees, comparison protocols and installed dependencies are not
bundled in this protocol-only export. The build script does not install them.

## Build and test

Point the environment variables to the external source trees and the prefix
containing their already-installed dependencies:

```bash
export MINBUCKET_ROOT=/path/to/MinBucket-MPSI
export EZPC_ROOT=/path/to/EzPC
export DEPENDENCY_PREFIX=/path/to/dependency-prefix

bash scripts/build.sh
python3 scripts/run_demo.py
python3 scripts/run_demo.py --esc-test
python3 scripts/run_validation.py
```

The build script configures a Release build and runs the native CTest tests.
The default demo uses three local parties with synthetic inputs. Runtime
outputs are created in `results/`, which is excluded by `.gitignore`.
The demo reads every input to calculate an independent plaintext correctness
oracle; it is intended for local tests.

## Input and participant entry point

Each input is UTF-8 TSV with a header `id<TAB>weight<TAB>features`.
Identifiers must be unique within each party. Weights are nonnegative integers
bounded by `--max-weight`. Features are single-line local strings without tabs.

For separate-party operation, invoke `build/mpwsi_party` for each party with
only that party's input. Party IDs run from 0 to T-1; party 0 is the coordinator.
Use `build/mpwsi_party --help` for arguments. The same public parameters and
ordered `--hosts` list must be provided to every party.

## Implementation scope

This is a research reference implementation under a semi-honest model and a
trusted experimental network. Authenticated transport, malicious-party checks
and BFV circuit privacy are not implemented. The finite BFV plaintext field
also introduces a statistical false-match bound. The coordinator observes the
protocol's opened weights and selected identifiers. Passing correctness tests
does not establish the full security claims of a protocol specification.

## License

A license for this repository has not yet been specified. External dependencies
retain their own licenses.
