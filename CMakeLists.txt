cmake_minimum_required(VERSION 3.16)
project(MWDA LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(MINBUCKET_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../MinBucket-MPSI" CACHE PATH "MinBucket-MPSI source checkout")
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SEAL 4.1 CONFIG REQUIRED)
find_package(volePSI CONFIG REQUIRED)
find_package(Microsoft.GSL CONFIG REQUIRED)
find_package(Kuku CONFIG REQUIRED)
find_package(OpenMP REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)
set(EZPC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../EzPC" CACHE PATH "EzPC source checkout")

# Reuse the original MIT-licensed APSU/FourQ OPRF point implementation and
# polynomial interpolation, rather than substituting plaintext membership.
set(APSU_COMMON "${MINBUCKET_ROOT}/uMCRG/MCRG/common")
set(APSU_VERSION "2.0")
set(APSU_VERSION_MAJOR 2)
set(APSU_VERSION_MINOR 0)
set(APSU_VERSION_PATCH 0)
configure_file("${APSU_COMMON}/apsu/config.h.in" "generated/apsu/config.h")
add_library(mpwsi_primitives STATIC
  "${APSU_COMMON}/apsu/oprf/ecpoint.cpp"
  "${APSU_COMMON}/apsu/util/interpolate.cpp"
  "${APSU_COMMON}/apsu/fourq/crypto_util.c"
  "${APSU_COMMON}/apsu/fourq/eccp2_core.c"
  "${APSU_COMMON}/apsu/fourq/eccp2_no_endo.c"
  "${APSU_COMMON}/apsu/fourq/eccp2.c"
  "${APSU_COMMON}/apsu/fourq/hash_to_curve.c"
  "${APSU_COMMON}/apsu/fourq/random.c")
target_compile_definitions(mpwsi_primitives PUBLIC __LINUX__ _AMD64_ USE_ENDO=true)
# FourQ's x64 field code aliases uint64_t arrays as uint128_t. GCC's
# strict-aliasing optimization is incompatible with those upstream casts.
target_compile_options(mpwsi_primitives PRIVATE -mavx2 -maes -mpclmul -fno-strict-aliasing)
target_include_directories(mpwsi_primitives PUBLIC "${APSU_COMMON}" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(mpwsi_primitives PUBLIC SEAL::seal Microsoft.GSL::GSL Kuku::kuku OpenSSL::Crypto)

add_library(mpwsi_core STATIC src/common.cpp src/tahe.cpp src/hashing.cpp src/bmwg.cpp src/plain_polynomial.cpp src/bfv_polynomial.cpp src/esc.cpp src/protocol.cpp)
target_include_directories(mpwsi_core PUBLIC include)
target_include_directories(mpwsi_core PRIVATE "${EZPC_ROOT}/SCI/src")
target_link_libraries(mpwsi_core PUBLIC mpwsi_primitives visa::volePSI Threads::Threads OpenMP::OpenMP_CXX ${GMP_LIBRARY})
set_source_files_properties(src/esc.cpp PROPERTIES COMPILE_OPTIONS "-maes;-msse4.1;-mavx2;-Wno-deprecated-declarations;-Wno-ignored-attributes" COMPILE_DEFINITIONS "EMP_USE_RANDOM_DEVICE=1")
target_compile_options(mpwsi_core PRIVATE -Wall -Wextra -Wpedantic)
add_executable(mpwsi_party src/main.cpp)
target_link_libraries(mpwsi_party PRIVATE mpwsi_core)
add_executable(mpwsi_tests tests/unit.cpp)
target_link_libraries(mpwsi_tests PRIVATE mpwsi_core)
enable_testing()
add_test(NAME mpwsi_unit COMMAND mpwsi_tests)
add_executable(mpwsi_bfv_tests tests/bfv_polynomial.cpp)
target_link_libraries(mpwsi_bfv_tests PRIVATE mpwsi_core)
add_test(NAME mpwsi_bfv_polynomial COMMAND mpwsi_bfv_tests)
add_executable(mpwsi_bfv_edge_tests tests/bfv_edge_cases.cpp)
target_link_libraries(mpwsi_bfv_edge_tests PRIVATE mpwsi_core)
add_test(NAME mpwsi_bfv_edge_cases COMMAND mpwsi_bfv_edge_tests)
add_executable(mpwsi_plain_tests tests/plain_polynomial.cpp)
target_link_libraries(mpwsi_plain_tests PRIVATE mpwsi_core)
add_test(NAME mpwsi_plain_polynomial COMMAND mpwsi_plain_tests)
