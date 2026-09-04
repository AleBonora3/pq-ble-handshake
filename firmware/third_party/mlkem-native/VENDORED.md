# Vendored mlkem-native

- Upstream project: `pq-code-package/mlkem-native`
- Upstream repository: https://github.com/pq-code-package/mlkem-native
- Version/tag: `v2.0.0`
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- License: Apache-2.0 OR ISC OR MIT (see `LICENSE`)

The files under `mlkem/` and the upstream `LICENSE` were copied byte-for-byte
from the commit above. No vendored cryptographic, arithmetic, FIPS-202,
zeroization, or verification source has been modified.

The local `.gitattributes` disables line-ending conversion for this subtree so
Windows `core.autocrlf` settings cannot change those upstream bytes.

This firmware vendors only the fixed-level portable source closure needed by
`mlkem/mlkem_native.c`. Native arithmetic backends, native FIPS-202 backends,
assembly compilation units, tests, proofs, examples, and upstream build-system
files are intentionally omitted.

The Zephyr application compiles only `mlkem/mlkem_native.c`; that single
compilation unit includes the selected portable arithmetic and FIPS-202 C
sources. The application CMake target supplies these configuration macros:

- `MLK_CONFIG_PARAMETER_SET=768`
- `MLK_CONFIG_NO_RANDOMIZED_API`
- `MLK_CONFIG_NAMESPACE_PREFIX=pqble_mlkem`
- `MLK_CONFIG_INTERNAL_API_QUALIFIER=static`

The following backend-selection macros are intentionally left undefined:

- `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH`
- `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202`

`MLK_CONFIG_NO_ASM` is also left undefined. This permits mlkem-native's small
inline-assembly value barriers and zeroization support, but does not enable an
optimized ML-KEM arithmetic or FIPS-202 backend.
