# piqaso\_sdk

A post-quantum cryptography (PQC) SDK for C, built on top of [WolfSSL](https://github.com/wolfSSL/wolfssl).  
Targets both ordinary Linux/host builds (via CMake) and OP-TEE OS Trusted Applications (via `sub.mk`).

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Algorithms](#supported-algorithms)
3. [Repository Layout](#repository-layout)
4. [Core Types](#core-types)
5. [Error Codes](#error-codes)
6. [Building (Host / CMake)](#building-host--cmake)
   - [Quick start](#quick-start)
   - [Using a pre-built WolfSSL](#using-a-pre-built-wolfssl)
   - [Pinning the WolfSSL version](#pinning-the-wolfssl-version)
   - [CMake options reference](#cmake-options-reference)
7. [Building for OP-TEE (sub.mk)](#building-for-op-tee-submk)
8. [Language Bindings (SWIG)](#language-bindings-swig)
   - [Python](#python-bindings)
   - [Java](#java-bindings)
   - [JavaScript (Node.js)](#javascript-bindings-nodejs--n-api)
   - [Other languages](#other-languages)
9. [Running the Tests](#running-the-tests)
10. [API Reference](#api-reference)
    - [ML-KEM (FIPS 203)](#ml-kem-fips-203)
    - [ML-DSA (FIPS 204)](#ml-dsa-fips-204)
    - [LMS / HSS (NIST SP 800-208)](#lms--hss-nist-sp-800-208)
    - [XMSS / XMSS^MT (NIST SP 800-208 / RFC 8391)](#xmss--xmssmt-nist-sp-800-208--rfc-8391)
    - [AES-GCM](#aes-gcm)
    - [AES-CBC](#aes-cbc)
11. [WolfSSL Configuration (`user_settings.h`)](#wolfssl-configuration-user_settingsh)
12. [Security Considerations](#security-considerations)
13. [Extending the SDK](#extending-the-sdk)

---

## Overview

`piqaso_sdk` wraps WolfSSL's native PQC implementations behind a consistent, allocation-based C API:

- Inputs and outputs are described by plain structs containing `piq_buffer` pointers.
- Every function that allocates output provides a matching `free_*` function.
- All feature flags are centralised in `user_settings.h`, shared between the CMake build and the OP-TEE `sub.mk` build.

---

## Supported Algorithms

| Algorithm | Standard | Security levels / parameter sets |
|---|---|---|
| ML-KEM (CRYSTALS-Kyber) | FIPS 203 | 512 (L1), 768 (L3), 1024 (L5) |
| ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | 44 (L2), 65 (L3), 87 (L5) |
| LMS / HSS | NIST SP 800-208 | L1H5W2, L1H10W2, L2H5W2, L2H10W2 |
| XMSS / XMSS^MT | NIST SP 800-208 / RFC 8391 | SHA2 trees of various heights |
| AES-GCM | NIST SP 800-38D | 128 / 192 / 256-bit keys |
| AES-CBC | NIST SP 800-38A | 128 / 192 / 256-bit keys + PKCS#7 |

---

## Repository Layout

```
piqaso_sdk/
├── CMakeLists.txt        # Host build (auto-downloads WolfSSL if needed)
├── sub.mk                # OP-TEE Trusted Application build
├── user_settings.h       # Shared WolfSSL feature-flag config
│
├── include/piqaso/
│   ├── structs.h         # piq_buffer — the universal byte-buffer type
│   ├── errors.h          # PIQ_* return codes
│   ├── mlkem.h           # ML-KEM public API
│   ├── mldsa.h           # ML-DSA public API
│   ├── lms.h             # LMS / HSS public API
│   ├── xmss.h            # XMSS / XMSS^MT public API
│   └── aes.h             # AES-GCM and AES-CBC public API
│
├── src/
│   ├── mlkem.c
│   ├── mldsa.c
│   ├── lms.c
│   ├── xmss.c
│   └── aes.c
│
└── test/
    ├── test_mlkem.c
    ├── test_mldsa.c
    ├── test_lms.c
    ├── test_xmss.c
    └── test_aes.c
```

---

## Core Types

### `piq_buffer` (`include/piqaso/structs.h`)

All binary data (keys, ciphertexts, signatures, plaintexts…) is exchanged via `piq_buffer`:

```c
struct piq_buffer {
    uint8_t *buffer;
    size_t   buffer_len;
};
```

When you construct an input `piq_buffer` that wraps caller-owned memory you do not need to free the struct itself — just put it on the stack:

```c
struct piq_buffer msg = {
    .buffer     = (uint8_t *)"hello",
    .buffer_len = 5,
};
```

Output `piq_buffer` objects are heap-allocated by the SDK and must be released via the matching `free_*` function (never call `free()` directly on SDK output structs).

---

## Error Codes

Defined in `include/piqaso/errors.h`:

| Constant | Value | Meaning |
|---|---|---|
| `PIQ_SUCCESS` | 0 | Operation succeeded |
| `PIQ_MEM_ERROR` | -1 | Memory allocation failure |
| `PIQ_INVALID_PARAMS` | -2 | NULL pointer or bad parameter |
| `PIQ_CRYPTO_ERROR` | -3 | WolfSSL operation failed |
| `PIQ_VERIFY_FAILED` | -4 | Signature / tag verification failed |
| `PIQ_RAND_ERROR` | -5 | Random-number generation failed |

All functions return `PIQ_SUCCESS` (0) on success and a negative value on failure.

---

## Building (Host / CMake)

### Requirements

- CMake ≥ 3.16
- A C11 compiler (GCC or Clang)
- Git (needed when WolfSSL is fetched automatically)

### Quick start

```bash
# From the repository root:
cmake -S . -B build
cmake --build build -j$(nproc)
```

On the first run CMake will automatically clone WolfSSL `v5.7.6-stable` from GitHub and build it as a static library inside the build tree. No manual WolfSSL installation is required.

### Using a pre-built WolfSSL

If you have already built WolfSSL (e.g. cross-compiled for a specific target), point CMake at the installation:

```bash
cmake -S . -B build -DWOLFSSL_ROOT=/path/to/wolfssl/install
cmake --build build -j$(nproc)
```

CMake will look for `$WOLFSSL_ROOT/lib/libwolfssl.a` and fail fast if it is not found.

WolfSSL must have been built with `WOLFSSL_USER_SETTINGS` defined so that it reads the same `user_settings.h` that piqaso_sdk uses.

If `WOLFSSL_ROOT` is not set, CMake also probes standard system paths (`/usr/local/lib`, `/usr/lib`) via `pkg-config` before falling back to the automatic FetchContent clone.

### Pinning the WolfSSL version

The default tag is `v5.7.6-stable`. To use a different release:

```bash
cmake -S . -B build -DWOLFSSL_GIT_TAG=v5.8.0-stable
cmake --build build -j$(nproc)
```

### CMake options reference

| Option | Default | Description |
|---|---|---|
| `WOLFSSL_ROOT` | *(empty)* | Path to a pre-built WolfSSL installation |
| `WOLFSSL_GIT_TAG` | `v5.7.6-stable` | WolfSSL git tag to clone when no local copy is found |
| `OPTEE` | `OFF` | Build for OP-TEE trusted world (disables host entropy) |
| `BUILD_SHARED` | `OFF` | Also build `piqaso_sdk` as a host-side shared library (`libpiqaso_sdk.so`) |
| `BUILD_BINDINGS` | `OFF` | Generate SWIG language bindings (implies `BUILD_SHARED`) |
| `BINDINGS_LANGUAGE` | `python` | SWIG target language: `python`, `java`, … |

---

## Building for OP-TEE (sub.mk)

`sub.mk` integrates piqaso_sdk into the standard OP-TEE Trusted Application build system.

### Prerequisites

- WolfSSL compiled separately for the OP-TEE target with `WOLFSSL_USER_SETTINGS` defined and `OPTEE=1`
- An OP-TEE build environment with `CROSS_COMPILE` and TA-SDK variables set

### Usage

In your TA's `Makefile` or `sub.mk`, set the two path variables and then include (or reference) the SDK `sub.mk`:

```makefile
PIQASO_SDK_DIR  := /path/to/piqaso_sdk
WOLFSSL_DIR     := /path/to/wolfssl-optee-install   # must contain include/ and lib/

include $(PIQASO_SDK_DIR)/sub.mk
```

`sub.mk` adds to the standard OP-TEE variables:

| Variable | What is added |
|---|---|
| `srcs-y` | `src/mldsa.c`, `src/mlkem.c`, `src/lms.c`, `src/xmss.c`, `src/aes.c` |
| `global-incdirs-y` | `include/`, `$(WOLFSSL_DIR)/include`, the SDK root (for `user_settings.h`) |
| `libdirs-y` | `$(WOLFSSL_DIR)/lib` |
| `libnames-y` | `wolfssl` |
| `cflags-y` | `-DOPTEE -DWOLFSSL_USER_SETTINGS` |

The `OPTEE` compile definition disables host-specific entropy paths inside the SDK and signals to `user_settings.h` that it is running inside a Trusted Application.

---

## Language Bindings (SWIG)

A SWIG interface file at `bindings/piqaso.i` exposes the SDK to any language SWIG supports. Bindings are **host-only** (they build a shared library) and are mutually exclusive with `-DOPTEE=ON`, which requires static linking inside a Trusted Application.

### Prerequisites

- SWIG ≥ 4.0
  ```bash
  sudo apt-get install -y swig
  ```
- Headers for the target language (e.g. `python3-dev`, `default-jdk`).

Enabling bindings automatically turns on `BUILD_SHARED`, which produces `libpiqaso_sdk.so` alongside the static archive.

### Python bindings

```bash
cmake -S . -B build -DBUILD_BINDINGS=ON
cmake --build build -j$(nproc)
```

The build emits:

- `build/_piqaso.so` — the loadable CPython extension module
- `build/python/piqaso.py` — the generated Python wrapper module
- `build/libpiqaso_sdk.so` — the underlying shared library

Run the bundled smoke test (it adds `build/` and `build/python/` to `sys.path` automatically):

```bash
python3 test/test_bindings.py
```

Minimal usage:

```python
import sys
sys.path[:0] = ['build', 'build/python']
import piqaso as p

rc, pk, sk = p.py_mldsa_keygen(p.MLDSA_LEVEL3)
rc, sig    = p.py_mldsa_sign(p.MLDSA_LEVEL3, sk, b'hello')
assert p.py_mldsa_verify(p.MLDSA_LEVEL3, pk, b'hello', sig) == p.PIQ_SUCCESS
```

The Python typemaps accept any bytes-like object (`bytes`, `bytearray`, `memoryview`) or `None`, and return `bytes` for every output buffer.

### Java bindings

Use a separate build directory to keep the generated JNI/Java sources isolated:

```bash
cmake -S . -B build-java -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=java
cmake --build build-java -j$(nproc)
```

The build emits:

- `build-java/libpiqaso.so` — the JNI shared library
- `build-java/java/*.java` — generated Java source files (package `com.piqaso`)
- `build-java/piqaso.jar` — the same sources packaged as a JAR

Compile and run the bundled test driver:

```bash
javac -cp build-java/piqaso.jar -d build-java/test_classes test/PiqasoTest.java
java  -cp build-java/piqaso.jar:build-java/test_classes \
      -Djava.library.path=build-java PiqasoTest
```

Minimal usage:

```java
import com.piqaso.piqaso;
import com.piqaso.piqasoConstants;

static { System.loadLibrary("piqaso"); }

byte[][] pk = new byte[1][], sk = new byte[1][];
piqaso.py_mldsa_keygen(piqasoConstants.MLDSA_LEVEL3, pk, sk);

byte[][] sig = new byte[1][];
piqaso.py_mldsa_sign(piqasoConstants.MLDSA_LEVEL3, sk[0], "hello".getBytes(), sig);

int rc = piqaso.py_mldsa_verify(
    piqasoConstants.MLDSA_LEVEL3, pk[0], "hello".getBytes(), sig[0]);
```

The Java typemaps accept `byte[]` (or `null`) for every input buffer. Each output buffer is delivered via a `byte[][]` holder of length ≥ 1: the callee fills `holder[0]` with a freshly allocated `byte[]`.

### JavaScript bindings (Node.js / N-API)

The JavaScript bindings target Node's stable **N-API** ABI via SWIG 4.2's `-napi` engine and `node-addon-api`. The result is a single `.node` addon that loads on any Node ≥ 16 without rebuilding.

**Additional prerequisites:**

- Node.js ≥ 16 (tested with v22) and `npm`
- The build helper package under `bindings/js/` (provides `node-addon-api` and `node-api-headers`):
  ```bash
  (cd bindings/js && npm install)
  ```
- A C++17 toolchain (`g++` or `clang++`)

Then configure and build:

```bash
cmake -S . -B build-js -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=javascript
cmake --build build-js -j$(nproc)
```

The build emits:

- `build-js/piqaso.node` — the loadable Node.js addon
- `build-js/libpiqaso_sdk.so` — the underlying shared library

Run the bundled smoke test:

```bash
LD_LIBRARY_PATH=build-js node test/test_bindings.js
```

Minimal usage:

```javascript
const p = require('./build-js/piqaso.node');

const [, pk, sk] = p.py_mldsa_keygen(p.MLDSA_LEVEL3);
const msg        = Buffer.from('hello');
const [, sig]    = p.py_mldsa_sign(p.MLDSA_LEVEL3, sk, msg);

const rc = p.py_mldsa_verify(p.MLDSA_LEVEL3, pk, msg, sig);
console.assert(rc === p.PIQ_SUCCESS);
```

The JavaScript typemaps accept `Buffer`, `Uint8Array`, or `null` for every input buffer. Functions with multiple output buffers return a JS `Array` of the form `[rc, buf1, buf2, ...]`; each output buffer is a Node `Buffer`. Functions with a single output buffer still return `[rc, buf]` for consistency with the multi-output case.

### Other languages

`bindings/piqaso.i` is structured so adding Ruby, Lua, Go, C#, etc. only requires pasting an analogous `#elif defined(SWIG<LANG>)` typemap block — the inline C wrapper layer is language-agnostic. Once typemaps exist, build with:

```bash
cmake -S . -B build-<lang> -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=<lang>
cmake --build build-<lang> -j$(nproc)
```

---

## Running the Tests

Tests are built automatically during the host CMake build (they are skipped when cross-compiling or when `OPTEE=ON`).

```bash
# Build everything
cmake -S . -B build
cmake --build build -j$(nproc)

# Run all tests via CTest
cd build
ctest --output-on-failure

# Or run individual test binaries directly
./build/test_mldsa
./build/test_mlkem
./build/test_lms
./build/test_xmss
./build/test_aes
```

Each test binary exercises key generation, signing / encapsulation / encryption, verification / decapsulation / decryption, and tamper-detection for all parameter sets of its algorithm.

---

## API Reference

### ML-KEM (FIPS 203)

Header: `include/piqaso/mlkem.h`

ML-KEM is a Key Encapsulation Mechanism. One party encapsulates a random shared secret using the recipient's public key; the recipient decapsulates using their private key. Both parties end up with the same 32-byte shared secret.

#### Security levels

| Constant | Algorithm | NIST security category |
|---|---|---|
| `MLKEM_LEVEL1` (1) | ML-KEM-512 | Category 1 (≥ AES-128) |
| `MLKEM_LEVEL3` (3) | ML-KEM-768 | Category 3 (≥ AES-192) |
| `MLKEM_LEVEL5` (5) | ML-KEM-1024 | Category 5 (≥ AES-256) |

#### Key generation

```c
struct mlkem_keygen_in kg_in = { .level = MLKEM_LEVEL3 };
struct mlkem_keygen_out *kg_out = NULL;

int ret = mlkem_keygen(&kg_in, &kg_out);
if (ret != PIQ_SUCCESS) { /* handle error */ }

// kg_out->public_key  — encapsulation key (send to encapsulating party)
// kg_out->private_key — decapsulation key (keep secret)

free_mlkem_keygen_out(kg_out);
```

#### Encapsulation (sender)

```c
struct mlkem_encaps_in enc_in = {
    .level      = MLKEM_LEVEL3,
    .public_key = recipient_public_key,  // piq_buffer *
};
struct mlkem_encaps_out *enc_out = NULL;

int ret = mlkem_encaps(&enc_in, &enc_out);
// Send enc_out->ciphertext to the recipient.
// Use enc_out->shared_secret locally.

free_mlkem_encaps_out(enc_out);
```

#### Decapsulation (recipient)

```c
struct mlkem_decaps_in dec_in = {
    .level       = MLKEM_LEVEL3,
    .private_key = kg_out->private_key,
    .ciphertext  = received_ciphertext,  // piq_buffer *
};
struct mlkem_decaps_out *dec_out = NULL;

int ret = mlkem_decaps(&dec_in, &dec_out);
// dec_out->shared_secret matches the sender's shared secret.

free_mlkem_decaps_out(dec_out);
```

---

### ML-DSA (FIPS 204)

Header: `include/piqaso/mldsa.h`

ML-DSA is a lattice-based digital signature scheme. A private key signs a message; any holder of the public key can verify the signature.

#### Security levels

| Constant | Algorithm | NIST security category |
|---|---|---|
| `MLDSA_LEVEL2` (2) | ML-DSA-44 | Category 2 (≥ SHA3-224) |
| `MLDSA_LEVEL3` (3) | ML-DSA-65 | Category 3 (≥ AES-192) |
| `MLDSA_LEVEL5` (5) | ML-DSA-87 | Category 5 (≥ AES-256) |

#### Key generation

```c
struct mldsa_keygen_in kg_in = { .level = MLDSA_LEVEL3 };
struct mldsa_keygen_out *kg_out = NULL;

int ret = mldsa_keygen(&kg_in, &kg_out);

// kg_out->public_key  — distribute to verifiers
// kg_out->private_key — keep secret

free_mldsa_keygen_out(kg_out);
```

#### Signing

```c
struct piq_buffer msg_buf = { .buffer = (uint8_t *)msg, .buffer_len = msg_len };

struct mldsa_sign_in sign_in = {
    .level       = MLDSA_LEVEL3,
    .private_key = kg_out->private_key,
    .message     = &msg_buf,
};
struct mldsa_sign_out *sign_out = NULL;

int ret = mldsa_sign(&sign_in, &sign_out);
// sign_out->signature — detached signature bytes

free_mldsa_sign_out(sign_out);
```

#### Verification

```c
struct mldsa_verify_in vfy_in = {
    .level      = MLDSA_LEVEL3,
    .public_key = kg_out->public_key,
    .message    = &msg_buf,
    .signature  = sign_out->signature,
};

int ret = mldsa_verify(&vfy_in);
// PIQ_SUCCESS       → valid
// PIQ_VERIFY_FAILED → invalid (signature or message was tampered)
```

---

### LMS / HSS (NIST SP 800-208)

Header: `include/piqaso/lms.h`

LMS (Leighton-Micali Signatures) is a **stateful** hash-based signature scheme. Each private key contains a finite pool of one-time signing keys.

> **Critical:** Every call to `lms_sign()` returns an `updated_private_key`. You **must** persist this updated key before signing again. Reusing a key state breaks security irreversibly.

#### Parameter sets

| Constant | Value | Levels | Height | Winternitz | Max signatures |
|---|---|---|---|---|---|
| `LMS_PARM_L1_H5_W2` | 2 | 1 | 5 | 2 | 32 |
| `LMS_PARM_L1_H10_W2` | 5 | 1 | 10 | 2 | 1 024 |
| `LMS_PARM_L2_H5_W2` | 14 | 2 | 5 | 2 | 1 024 |
| `LMS_PARM_L2_H10_W2` | 17 | 2 | 10 | 2 | ~1 000 000 |

#### Key generation

```c
struct lms_keygen_in kg_in = { .parm = LMS_PARM_L1_H10_W2 };
struct lms_keygen_out *kg_out = NULL;

int ret = lms_keygen(&kg_in, &kg_out);

// Persist kg_out->private_key before the first sign call.
// kg_out->public_key can be distributed freely.
```

#### Signing

```c
struct piq_buffer msg_buf = { .buffer = data, .buffer_len = data_len };

struct lms_sign_in sign_in = {
    .parm        = LMS_PARM_L1_H10_W2,
    .private_key = current_private_key,  // from keygen or previous sign
    .message     = &msg_buf,
};
struct lms_sign_out *sign_out = NULL;

int ret = lms_sign(&sign_in, &sign_out);

// IMMEDIATELY persist sign_out->updated_private_key to durable storage
// before any further operations.
// sign_out->signature — the detached signature
```

#### Verification

```c
struct lms_verify_in vfy_in = {
    .parm       = LMS_PARM_L1_H10_W2,
    .public_key = kg_out->public_key,
    .message    = &msg_buf,
    .signature  = sign_out->signature,
};

int ret = lms_verify(&vfy_in);
// PIQ_SUCCESS       → valid
// PIQ_VERIFY_FAILED → invalid
```

---

### XMSS / XMSS^MT (NIST SP 800-208 / RFC 8391)

Header: `include/piqaso/xmss.h`

XMSS is another **stateful** hash-based signature scheme. Parameter sets are identified by strings rather than integer constants.

> **Critical:** Same state-management rules as LMS — always persist `updated_private_key` immediately after each sign call.

#### Parameter strings

**XMSS (single tree):**

| String | Max signatures |
|---|---|
| `"XMSS-SHA2_10_256"` | 1 024 |
| `"XMSS-SHA2_16_256"` | 65 536 |
| `"XMSS-SHA2_20_256"` | ~1 000 000 |

**XMSS^MT (multi-tree):**

| String | Total height | Levels |
|---|---|---|
| `"XMSSMT-SHA2_20/2_256"` | 20 | 2 |
| `"XMSSMT-SHA2_20/4_256"` | 20 | 4 |
| `"XMSSMT-SHA2_40/2_256"` | 40 | 2 |
| `"XMSSMT-SHA2_40/4_256"` | 40 | 4 |
| `"XMSSMT-SHA2_40/8_256"` | 40 | 8 |
| `"XMSSMT-SHA2_60/3_256"` | 60 | 3 |
| `"XMSSMT-SHA2_60/6_256"` | 60 | 6 |
| `"XMSSMT-SHA2_60/12_256"` | 60 | 12 |

#### Key generation

```c
struct xmss_keygen_in kg_in = { .param_str = "XMSS-SHA2_10_256" };
struct xmss_keygen_out *kg_out = NULL;

int ret = xmss_keygen(&kg_in, &kg_out);

// Persist kg_out->private_key before the first sign call.
```

#### Signing

```c
struct piq_buffer msg_buf = { .buffer = data, .buffer_len = data_len };

struct xmss_sign_in sign_in = {
    .param_str   = "XMSS-SHA2_10_256",
    .private_key = current_private_key,
    .message     = &msg_buf,
};
struct xmss_sign_out *sign_out = NULL;

int ret = xmss_sign(&sign_in, &sign_out);

// IMMEDIATELY persist sign_out->updated_private_key.
// sign_out->signature — the detached signature
```

#### Verification

```c
struct xmss_verify_in vfy_in = {
    .param_str  = "XMSS-SHA2_10_256",
    .public_key = kg_out->public_key,
    .message    = &msg_buf,
    .signature  = sign_out->signature,
};

int ret = xmss_verify(&vfy_in);
// PIQ_SUCCESS       → valid
// PIQ_VERIFY_FAILED → invalid
```

---

### AES-GCM

Header: `include/piqaso/aes.h`

AES-GCM provides authenticated encryption with associated data (AEAD). The 16-byte authentication tag guarantees both confidentiality and integrity.

- IV size: **12 bytes** (96-bit nonce, NIST recommended)
- Tag size: **16 bytes**
- Key sizes: 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes
- Pass `iv = NULL` to have the SDK generate a cryptographically random nonce; the used IV is always returned in the output struct

#### Encryption

```c
struct piq_buffer key_buf  = { key,       32 };      // AES-256
struct piq_buffer plain    = { plaintext, plain_len };
struct piq_buffer aad_buf  = { aad,       aad_len };  // optional

struct aesgcm_encrypt_in enc_in = {
    .key       = &key_buf,
    .iv        = NULL,       // auto-generate a random 12-byte nonce
    .plaintext = &plain,
    .aad       = &aad_buf,  // or NULL if not needed
};
struct aesgcm_encrypt_out *enc_out = NULL;

int ret = aesgcm_encrypt(&enc_in, &enc_out);

// Transmit: enc_out->iv, enc_out->ciphertext, enc_out->tag
// (and the AAD separately if used)

free_aesgcm_encrypt_out(enc_out);
```

#### Decryption

```c
struct aesgcm_decrypt_in dec_in = {
    .key        = &key_buf,
    .iv         = received_iv,
    .ciphertext = received_ciphertext,
    .tag        = received_tag,
    .aad        = &aad_buf,   // must match what was used during encryption
};
struct aesgcm_decrypt_out *dec_out = NULL;

int ret = aesgcm_decrypt(&dec_in, &dec_out);
// PIQ_SUCCESS       → authenticated + decrypted; plaintext in dec_out->plaintext
// PIQ_VERIFY_FAILED → tag mismatch; output plaintext is zeroed

free_aesgcm_decrypt_out(dec_out);
```

---

### AES-CBC

Header: `include/piqaso/aes.h`

AES-CBC provides conventional (non-authenticated) block-cipher encryption with PKCS#7 padding. Plaintext does not need to be block-aligned.

- IV size: **16 bytes** (one AES block)
- Key sizes: 16, 24, or 32 bytes
- Pass `iv = NULL` to have the SDK generate a random IV

> **Note:** AES-CBC does not provide authentication. Prefer AES-GCM unless you need CBC for interoperability reasons. When using CBC, authenticate ciphertexts externally (e.g. with an ML-DSA signature or an HMAC).

#### Encryption

```c
struct piq_buffer key_buf = { key, 32 };
struct piq_buffer plain   = { plaintext, plain_len };

struct aescbc_encrypt_in enc_in = {
    .key       = &key_buf,
    .iv        = NULL,    // auto-generate a random 16-byte IV
    .plaintext = &plain,
};
struct aescbc_encrypt_out *enc_out = NULL;

int ret = aescbc_encrypt(&enc_in, &enc_out);

// Transmit: enc_out->iv, enc_out->ciphertext

free_aescbc_encrypt_out(enc_out);
```

#### Decryption

```c
struct aescbc_decrypt_in dec_in = {
    .key        = &key_buf,
    .iv         = received_iv,
    .ciphertext = received_ciphertext,
};
struct aescbc_decrypt_out *dec_out = NULL;

int ret = aescbc_decrypt(&dec_in, &dec_out);
// dec_out->plaintext — PKCS#7 padding is stripped automatically

free_aescbc_decrypt_out(dec_out);
```

---

## WolfSSL Configuration (`user_settings.h`)

All WolfSSL feature flags are declared in `user_settings.h` at the repository root. This file is consumed by both the CMake build and the OP-TEE `sub.mk` build via the `WOLFSSL_USER_SETTINGS` compile definition.

Key settings enabled:

| Define | Purpose |
|---|---|
| `NO_FILESYSTEM` | TAs have no filesystem access |
| `SINGLE_THREADED` | TAs are single-threaded |
| `WOLFSSL_SMALL_STACK` | Reduces stack usage (critical for TAs) |
| `TFM_TIMING_RESISTANT` | Side-channel hardening for big-integer math |
| `ECC_TIMING_RESISTANT` | Side-channel hardening for ECC |
| `WC_RSA_BLINDING` | RSA blinding against timing attacks |
| `HAVE_DILITHIUM` / `WOLFSSL_WC_DILITHIUM` | ML-DSA (native wolfCrypt) |
| `WOLFSSL_HAVE_KYBER` / `WOLFSSL_WC_KYBER` | ML-KEM (native wolfCrypt) |
| `WOLFSSL_HAVE_LMS` / `WOLFSSL_WC_LMS` | LMS/HSS (native wolfCrypt) |
| `WOLFSSL_HAVE_XMSS` / `WOLFSSL_WC_XMSS` | XMSS (native wolfCrypt) |
| `HAVE_AES_CBC` / `HAVE_AESGCM` | AES block cipher modes |
| `WOLFSSL_SHAKE128` / `WOLFSSL_SHAKE256` | Required by ML-KEM and ML-DSA |
| `WOLFSSL_EXPERIMENTAL` | Required by Kyber in this WolfSSL version |

Unused protocol layers (`NO_OLD_TLS`, `NO_PSK`, `NO_MD4`, `NO_RC4`, `NO_DES3`, `NO_RC2`) are disabled to keep binary size small — important for Trusted Applications.

To enable or disable an algorithm, edit `user_settings.h` and rebuild. No CMake option changes are required.

---

## Security Considerations

### Stateful signatures (LMS and XMSS)

LMS and XMSS are **stateful**. Each signing operation consumes one one-time key from a finite pool. The rules are strict:

1. **Always persist `updated_private_key` immediately** after `lms_sign()` or `xmss_sign()` returns, before doing anything else with the result.
2. **Never sign with the same private key state twice.** If your system crashes between signing and persisting, the old state must not be reused.
3. Choose a parameter set that provides more signatures than you will ever need. Once the pool is exhausted, no more signatures can be produced and a new key pair must be generated.

For OP-TEE use-cases, store the private key in secure storage (TA secure storage API) and use atomic write semantics where possible.

### Key sizes and NIST security levels

For long-term post-quantum security, prefer the higher security levels:

- ML-KEM-1024 (Level 5) for key encapsulation
- ML-DSA-87 (Level 5) for signatures

Level 3 variants offer a reasonable balance of performance and security for most applications.

### AES key size

Use AES-256 (32-byte keys) alongside PQC algorithms to maintain consistent 256-bit security.

### IV / nonce uniqueness for AES-GCM

Never reuse an IV with the same AES-GCM key. The SDK generates a random IV when `iv = NULL` is passed, which is safe in practice, but if you supply IVs manually you must guarantee uniqueness across all encryptions under the same key.

