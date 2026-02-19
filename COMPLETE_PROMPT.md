# JWTTokenLib — Complete Project Specification Prompt
## (Use this prompt to recreate or extend the project with any AI tool)

---

## Context

This document is the complete specification and implementation prompt for the
**JWTTokenLib** project. Use this document if you need to:
- Recreate the project from scratch
- Ask an AI assistant to extend or modify the library
- Onboard a new developer to understand all decisions made
- Audit what was built and why

---

## The Complete Prompt

---

```
Please create a complete, production-ready JWT token generation library for
LoadRunner Enterprise (LRE) based on the following detailed specifications.

================================================================================
BUSINESS CONTEXT
================================================================================

LoadRunner Enterprise (LRE) is used for NFT (Non-Functional Testing) load tests.
Virtual User Generator (VuGen) creates and enhances test scripts.
Scripts are uploaded to LRE to schedule and run load tests.

Many applications use JWT tokens with PS256, RS256, HS256 algorithms for API
authentication. Load test engineers need to generate these tokens during tests.

PROBLEMS WITH CURRENT APPROACHES:
- jsrassign.js (JavaScript JWT library) cannot handle high concurrent load
- Each team implements their own solution - no standardization
- Complex setup required - not suitable for non-technical users
- No support for loading private keys from rts.yaml parameters

REQUIRED SOLUTION:
A centralized library that:
- Users call with ONE simple function
- Requires ZERO configuration by end users
- Achieves high performance (designed for 100-1000+ TPS)
- Works on both LRE protocols: WEB HTTP/HTML (C) and DevWeb (JavaScript)
- Requires no extra installations on Load Generators

================================================================================
ENVIRONMENT DETAILS
================================================================================

PLATFORMS:
- Windows Server 2022 / 2025 (Load Generators)
- AWS RedHat Linux / Amazon Linux 2023 (Load Generators)

LRE VERSIONS:
- OpenText LoadRunner Enterprise 2025.1
- OpenText LoadRunner Enterprise 26.1 (upgrade target)

DEVWEB NODE.JS VERSION:
- LRE DevWeb runtime uses Node.js v22.11.0

PROTOCOLS IN USE:
1. WEB HTTP/HTML - C language protocol (VuGen)
2. DevWeb - JavaScript SDK protocol (LRE 26.1)

ACTUAL LOAD:
- Current realistic TPS: ~100 TPS
- Future requirement: potentially higher, unknown
- Must be designed for scale without bottlenecks

================================================================================
TECHNICAL REQUIREMENTS
================================================================================

TECHNOLOGY STACK:
- Core language: C11 standard
- Cryptography: OpenSSL 3.x
- Build system: CMake 3.15+
- Windows compiler: MSVC 2019+ (Visual Studio)
- Linux compiler: GCC 9+
- DevWeb: Pure JavaScript using Node.js built-in 'crypto' module (NO native addon)

KEY DECISION - DEVWEB APPROACH:
Do NOT use a Node.js native addon (.node file) for DevWeb. Instead, use a
pure JavaScript module that uses Node.js's built-in 'crypto' module.
Reasons:
  - Node.js built-in crypto supports all required algorithms natively
  - No ABI compatibility issues across LRE versions
  - No compilation step needed
  - Single .js file copied to script folder - zero configuration
  - Works with any Node.js v14+ including v22.11.0 in LRE 26.1

KEY DECISION - WINDOWS DLL:
Statically link OpenSSL into the DLL on Windows so that only ONE file
(JWTTokenLib.dll) needs to be deployed. No libssl DLLs alongside it.

================================================================================
SUPPORTED ALGORITHMS (Priority Order)
================================================================================

1. PS256 (RSA-PSS SHA-256)    ← PRIMARY - most users
2. RS256 (RSA PKCS#1 SHA-256) ← SECONDARY - common in legacy APIs
3. HS256 (HMAC SHA-256)       ← COMMON - internal/microservice APIs
4. ES256 (ECDSA P-256)        ← SUPPORTED

Also support all variants:
- PS384, PS512 (RSA-PSS with SHA-384/512)
- RS384, RS512 (RSA PKCS#1 with SHA-384/512)
- HS384, HS512 (HMAC with SHA-384/512)
- ES384, ES512 (ECDSA with P-384/P-521)

ECDSA CRITICAL DETAIL:
OpenSSL EVP_DigestSign produces ECDSA signatures in ASN.1 DER format.
JWT RFC 7518 §3.4 requires raw R||S concatenation.
Must convert: SEQUENCE { INTEGER r, INTEGER s } → raw R bytes || raw S bytes
Coordinate sizes: ES256=32, ES384=48, ES512=66 bytes each.

RSA-PSS CRITICAL DETAIL:
- Padding: RSA_PKCS1_PSS_PADDING
- Salt length: RSA_PSS_SALTLEN_DIGEST (salt length = hash output length)
- This matches RFC 7518 §3.5 requirements

================================================================================
KEY AUTO-DETECTION (USER CONVENIENCE)
================================================================================

The key_or_secret parameter is auto-detected - users don't configure anything:

  If starts with "-----BEGIN"   → PEM content string (from rts.yaml parameter)
  If ends with ".pem"           → PEM file path (from script extras/ folder)
  If ends with ".p12" or ".pfx" → PKCS#12 file path (no password)
  Anything else                 → HMAC secret string (for HS* algorithms)

KEY FORMAT REQUIREMENTS:
- PEM files: unencrypted (no passphrase protection)
- PKCS#12: no password
- JKS format: NOT supported (Java KeyStore is Java-proprietary)
- Key content as string from rts.yaml: full PEM including BEGIN/END headers

================================================================================
TOKEN REFRESH FOR LONG LOAD TEST RUNS
================================================================================

Some users run tests for 2+ hours with 10-15 minute token expiry.
The solution is simple: provide JWT_Is_Token_Expiring() helper function.

IMPORTANT: No token caching needed.
- Each VUser generates a UNIQUE token (unique sub, jti, iat, exp)
- VUsers check JWT_Is_Token_Expiring() and call JWT_Generate() again when needed
- No shared cache, no mutex, no complexity

VuGen usage pattern:
  if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300)) {
      JWT_Generate("PS256", payload, key, jwt_token, sizeof(jwt_token));
  }

DevWeb usage pattern:
  if (!global.token || jwt.isExpiring(global.token, 300)) {
      global.token = jwt.generate({...});
  }

================================================================================
KEY FILE LOCATIONS
================================================================================

WEB HTTP/HTML Protocol:
- Private key goes in script's extras/ folder
- Accessed as relative path: "extras/private_key.pem"
- VuGen sets CWD to script folder during execution
- For Linux LGs: same relative path works

DevWeb Protocol:
- Private key goes in script ROOT folder (same level as main.js)
- Accessed as: "./private_key.pem"
- NOT in extras/ folder - DevWeb uses script root as working directory

rts.yaml Alternative (both protocols):
- User stores full PEM content as a parameter value in rts.yaml
- C:  JWT_Generate("PS256", payload, lr_eval_string("{PrivateKeyPEM}"), ...)
- JS: jwt.generate({ key: load.params.get('PrivateKeyPEM'), ... })

================================================================================
PROJECT FILE STRUCTURE
================================================================================

JWTTokenLib/
│
├── CMakeLists.txt              # Build config - Windows DLL + Linux SO
├── README.md                  # Quick start guide
├── USERGUIDE.md               # Non-technical step-by-step guide
├── REQUIREMENTS.md            # Prerequisites and system requirements
├── TROUBLESHOOTING.md         # Common issues and solutions
├── COMPLETE_PROMPT.md         # This file - full specification
│
├── jwt-lib.js                 # DevWeb pure JavaScript module
│                               # (copy to DevWeb script root folder)
│
├── include/
│   └── jwtlib.h               # Public C API header
│                               # (exported functions, error codes)
│
├── src/
│   ├── jwt_core.h             # Internal header (all internal types/protos)
│   ├── jwt_core.c             # Main JWT generation pipeline
│   │
│   ├── algorithms/
│   │   ├── hs256.c            # HMAC-SHA signing (HS256/384/512)
│   │   ├── rs256.c            # RSA PKCS#1 v1.5 (RS256/384/512)
│   │   ├── ps256.c            # RSA-PSS (PS256/384/512) ← PRIMARY
│   │   └── es256.c            # ECDSA with DER→R||S (ES256/384/512)
│   │
│   ├── utils/
│   │   ├── base64url.c        # Base64URL encode/decode (RFC 4648 §5)
│   │   └── key_manager.c      # Key auto-detection and loading
│   │
│   └── bindings/
│       └── c_exports.c        # DLL exported functions implementation
│
├── tests/
│   ├── test_standalone.c      # C test suite (all algorithms + error cases)
│   └── test_devweb.js         # DevWeb/Node.js test suite
│
└── examples/
    ├── vugen_example.c         # Complete production VuGen script
    └── devweb_example.js       # Complete production DevWeb script

================================================================================
C PUBLIC API (include/jwtlib.h)
================================================================================

Error codes:
  #define JWT_SUCCESS               0
  #define JWT_ERROR_INVALID_ALG    -1   // Unknown algorithm name
  #define JWT_ERROR_INVALID_KEY    -2   // Invalid key or secret
  #define JWT_ERROR_INVALID_JSON   -3   // Malformed JSON payload
  #define JWT_ERROR_BUFFER_SMALL   -4   // Output buffer too small
  #define JWT_ERROR_SIGN_FAILED    -5   // Cryptographic operation failed
  #define JWT_ERROR_NULL_POINTER   -6   // NULL argument passed
  #define JWT_ERROR_FILE_NOT_FOUND -7   // Key file not found
  #define JWT_ERROR_MEMORY         -8   // malloc() failed
  #define JWT_ERROR_ENCODE         -9   // Base64URL encoding failed

Exported functions:

  int JWT_Generate(
      const char* algorithm,      // "PS256", "RS256", "HS256", "ES256", etc.
      const char* payload_json,   // JSON string with claims
      const char* key_or_secret,  // Auto-detected: file/content/secret
      char*       output_token,   // Output buffer (recommend 4096 bytes)
      int         buffer_size     // Size of output buffer
  );

  int JWT_Is_Token_Expiring(
      const char* token,          // Current JWT token string
      int         threshold_seconds // Warn if expiring within N seconds
  );
  // Returns: 1=expiring, 0=valid, -1=no exp claim or invalid token

  const char* JWT_Get_Error_Message(int error_code);
  // Returns static string description of error code

  const char* JWT_Get_Version(void);
  // Returns "1.0.0"

  int JWT_Is_Algorithm_Supported(const char* algorithm);
  // Returns 1 if supported, 0 if not

Platform exports:
  Windows: __declspec(dllexport) / __declspec(dllimport)
  Linux:   __attribute__((visibility("default")))
  CMake:   -fvisibility=hidden on Linux (only JWTLIB_API symbols exported)

================================================================================
JAVASCRIPT API (jwt-lib.js for DevWeb)
================================================================================

The DevWeb module uses ONLY Node.js built-in modules:
  - require('crypto') for all cryptographic operations
  - require('fs') for reading key files
  No external npm dependencies whatsoever.

Exported functions:

  generate(options) → string
    options.algorithm  {string}  Required: 'PS256', 'RS256', 'HS256', etc.
    options.payload    {Object}  Required: claims object (auto JSON.stringify)
    options.keyPath    {string}  Path to PEM file (relative to script root)
    options.key        {string}  PEM content string (from rts.yaml param)
    options.secret     {string}  HMAC secret (for HS* algorithms only)
    options.header     {Object}  Optional extra header fields (e.g. {kid:'x'})
    Returns: JWT token string
    Throws: Error on invalid input or signing failure

  decode(token) → Object
    Returns decoded payload object (NO signature verification)
    Throws: Error on invalid JWT format

  isExpiring(token, thresholdSeconds) → boolean
    Returns true if token expires within thresholdSeconds
    Returns true if token has no 'exp' claim (treat as needing refresh)
    Returns true if token cannot be decoded (treat as needing refresh)

  getVersion() → string
    Returns "1.0.0"

  isAlgorithmSupported(algorithm) → boolean
    Returns true if algorithm is in supported list

ECDSA DER→R||S conversion in jwt-lib.js:
  Node.js crypto.sign() for EC keys returns ASN.1 DER.
  Must manually parse: SEQUENCE { INTEGER r, INTEGER s }
  Strip leading 0x00 sign bytes from r and s.
  Right-align in curve-sized buffers (32/48/66 bytes each).
  Concatenate: R bytes || S bytes = JWT signature.

================================================================================
CMAKE BUILD CONFIGURATION
================================================================================

Windows:
  - Target: SHARED library named JWTTokenLib (.dll)
  - OPENSSL_USE_STATIC_LIBS=ON (default)
  - Extra link libs: ws2_32, crypt32
  - Compiler: MSVC with /O2 /GL /W3
  - Define JWTLIB_EXPORTS during build
  - Output: build/bin/Release/JWTTokenLib.dll

Linux:
  - Target: SHARED library named JWTTokenLib (.so)
  - POSITION_INDEPENDENT_CODE=ON
  - -fvisibility=hidden (hide all except JWTLIB_API)
  - Compiler: GCC with -O2 -Wall -Wextra
  - Output: build/lib/libJWTTokenLib.so

Both:
  - Include paths: include/, src/, OpenSSL headers
  - Test executable: tests/test_standalone.c → test_jwt binary
  - Install rules: DLL/SO → dist/ folder, jwtlib.h → dist/include/

OpenSSL location hint for Windows:
  cmake .. -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"

================================================================================
INTERNAL ARCHITECTURE
================================================================================

HEADER HIERARCHY:
  jwtlib.h     → public API (error codes, JWTLIB_API, function declarations)
  jwt_core.h   → internal master header (includes jwtlib.h, openssl headers,
                  defines jwt_alg_t enum, jwt_key_type_t enum, all internal
                  function prototypes, platform compat macros)
  All .c files → #include "jwt_core.h" only (gets everything via master header)
  CMake        → adds src/ and include/ to include path so relative paths work

ALGORITHM ENUM (jwt_alg_t):
  JWT_ALG_UNKNOWN, JWT_ALG_HS256..HS512, JWT_ALG_RS256..RS512,
  JWT_ALG_PS256..PS512, JWT_ALG_ES256..ES512
  Ranges used for dispatch: HS256-HS512, RS256-RS512, PS256-PS512, ES256-ES512

KEY TYPE ENUM (jwt_key_type_t):
  KEY_PEM_FILE, KEY_PEM_CONTENT, KEY_P12_FILE, KEY_HMAC_SECRET

JWT GENERATION PIPELINE (jwt_core.c):
  1. jwt_parse_algorithm() → jwt_alg_t
  2. jwt_get_hash_for_alg() → EVP_MD*
  3. Build header JSON: {"alg":"PS256","typ":"JWT"}
  4. base64url_encode(header_json) → header_b64
  5. base64url_encode(payload_json) → payload_b64  [malloc]
  6. Build signing_input = header_b64 + "." + payload_b64  [malloc]
  7. jwt_detect_key_type() → jwt_key_type_t
  8. Dispatch to: jwt_sign_hmac() / jwt_sign_rsa() / jwt_sign_rsa_pss() / jwt_sign_ecdsa()
     (For asymmetric: jwt_load_private_key() first, EVP_PKEY_free() after)
  9. base64url_encode(signature) → sig_b64
  10. Assemble: header_b64 + "." + payload_b64 + "." + sig_b64 → output_token
  11. Cleanup: free(payload_b64), free(signing_input), EVP_PKEY_free(pkey)

THREAD SAFETY:
  All functions use local variables only. No global mutable state.
  OpenSSL 3.x is thread-safe by default.
  Safe for concurrent VUsers without synchronization.

MEMORY MANAGEMENT:
  Only two heap allocations per JWT_Generate() call:
  - payload_b64 buffer (freed at end)
  - signing_input buffer (freed at end)
  All other buffers are stack-allocated.
  EVP_PKEY and EVP_MD_CTX properly freed in all paths (goto cleanup pattern).

BASE64URL (RFC 4648 §5):
  Standard Base64 alphabet, then replace: '+' → '-', '/' → '_', strip '='
  Implemented from scratch (no dependencies).
  Encoding: 3 input bytes → 4 output chars, with correct trailing byte handling.
  Decoding: accepts both standard (+/) and URL-safe (-_) characters.

JWT_Is_Token_Expiring() implementation:
  - Find dots in token to locate payload section
  - base64url_decode() the payload
  - Simple strstr() search for "\"exp\"" in JSON (no full JSON parser)
  - atol() to get Unix timestamp
  - Compare with time(NULL) + threshold_seconds

================================================================================
DEPLOYMENT SUMMARY
================================================================================

STEP 1 (one-time, by build engineer):
  Build DLL/SO per platform instructions in USERGUIDE.md.

STEP 2 (one-time per LG, by LRE administrator):
  Windows LG: Copy JWTTokenLib.dll → LoadRunner bin\ folder
  Linux LG:   Copy libJWTTokenLib.so → LoadRunner lib/ folder

STEP 3 (per script, by test engineer):
  WEB HTTP/HTML: Add function declarations to globals.h
                 Call lr_load_dll() in vuser_init()
                 Place private_key.pem in extras/ folder
                 Call JWT_Generate() in Action()

  DevWeb:        Copy jwt-lib.js to script root folder
                 Copy private_key.pem to script root folder
                 Add require('./jwt-lib') in main.js
                 Call jwt.generate() in load.action()

NO OTHER STEPS. No npm install. No configuration files. No environment variables.

================================================================================
KEY DESIGN DECISIONS AND RATIONALE
================================================================================

DECISION 1: Pure JS for DevWeb (not a native .node addon)
  RATIONALE: The DevWeb docs confirm CommonJS modules work. Native addons
  are not documented and risk ABI mismatch if LRE updates Node.js version.
  Node.js v22.11.0 built-in crypto is fully capable of all required algorithms.
  Single .js file with zero dependencies is simpler and more maintainable.

DECISION 2: Static OpenSSL linking on Windows
  RATIONALE: Users need only ONE file (JWTTokenLib.dll) to deploy.
  If libcrypto/libssl DLLs were separate, users would need to manage 3 files
  and version compatibility. Static linking ensures zero deployment friction.

DECISION 3: Auto-detect key type from string content
  RATIONALE: Users should not need to specify key type. A PEM file path
  clearly differs from PEM content (starts with "-----BEGIN"). HMAC secrets
  are neither. This makes the API simpler without losing flexibility.

DECISION 4: Single output buffer (not heap-allocated return value)
  RATIONALE: VuGen C scripts use stack buffers (char token[4096]).
  Returning a heap-allocated string would require the user to free it,
  which VuGen scripts cannot easily do. Caller-owned buffer is idiomatic C.

DECISION 5: No token caching
  RATIONALE: Every VUser generates a unique token (unique sub, jti, iat).
  Caching tokens would mean sharing tokens between VUsers (wrong behavior)
  or per-VUser caching (same as just regenerating). JWT_Is_Token_Expiring()
  gives users the ability to refresh only when needed.

DECISION 6: No JKS support
  RATIONALE: JKS is a Java-proprietary format requiring Java libraries.
  OpenSSL (our crypto backend) cannot read JKS natively. Supporting it would
  require bundling Java or implementing a JKS parser (complex and fragile).
  Users can convert JKS to PEM once using keytool + openssl.

DECISION 7: Linux uses dynamic OpenSSL (not static)
  RATIONALE: OpenSSL is a system package on RedHat/Amazon Linux.
  Static linking on Linux is non-trivial and unnecessary when the system
  provides a compatible version. Dynamic linking is standard Linux practice.

================================================================================
TESTING REQUIREMENTS
================================================================================

C TEST SUITE (tests/test_standalone.c):
  - Version and algorithm support checks
  - HS256/384/512 with correct secret
  - HS256 with empty secret → JWT_ERROR_INVALID_KEY
  - PS256/RS256 with PEM file → correct header prefix
  - PS256/RS256 with PEM content string (rts.yaml scenario)
  - ES256 with EC key file
  - NULL argument handling → JWT_ERROR_NULL_POINTER
  - Invalid algorithm names → JWT_ERROR_INVALID_ALG
  - Buffer too small → JWT_ERROR_BUFFER_SMALL
  - Non-existent key file → JWT_ERROR_FILE_NOT_FOUND
  - JWT_Is_Token_Expiring: positive/negative/edge cases
  - Performance: HS256 and PS256 TPS measurement

DEVWEB TEST SUITE (tests/test_devweb.js):
  - All same algorithm tests as C suite
  - HS256 deterministic check (same input → same output)
  - PS256 non-deterministic check (PSS uses random salt → different each time)
  - Key from file vs key from string (rts.yaml scenario)
  - Custom header fields (kid)
  - decode() payload extraction
  - isExpiring() positive/negative/no-exp cases
  - Error handling (missing args, wrong algorithm, missing key)
  - Performance: HS256 > 1000 TPS baseline
  - Standalone execution: node tests/test_devweb.js (no LRE needed)

================================================================================
DOCUMENTATION REQUIREMENTS
================================================================================

README.md:
  - Quick start (< 5 minutes to copy and use)
  - Supported algorithms table
  - Both VuGen and DevWeb code examples
  - Key input options table (auto-detection)
  - Token refresh pattern
  - Key generation commands
  - Build from source instructions
  - Error codes reference
  - Performance numbers
  - Deployment checklist

USERGUIDE.md:
  - Written for NON-TECHNICAL users
  - Step-by-step with exact commands to type
  - Covers full build process (OpenSSL install, CMake install, VS install)
  - Covers deployment to LGs
  - Covers using in VuGen scripts (with complete globals.h + vuser_init + Action)
  - Covers using in DevWeb scripts (with complete main.js example)
  - Key generation steps
  - Token verification at jwt.io
  - Quick reference checklist at end

REQUIREMENTS.md:
  - Build machine requirements (Windows and Linux)
  - Load Generator requirements (Windows and Linux)
  - LRE version requirements
  - VuGen script requirements
  - DevWeb script requirements
  - Private key requirements
  - Compatibility matrix
  - What is NOT needed (simplifies user mental model)

TROUBLESHOOTING.md:
  - WEB HTTP/HTML issues (DLL not found, key not found, sign failed, buffer small)
  - DevWeb issues (MODULE_NOT_FOUND, key file, PEM encoding)
  - Build issues (Windows CMake, OpenSSL static, MSVC linker)
  - Build issues (Linux dnf, LD_LIBRARY_PATH)
  - API returns 401 (wrong algorithm, wrong key, clock skew, missing claims)
  - Debugging tips (verbose logging, jwt.io verification)

COMPLETE_PROMPT.md:
  - This document - full specification for AI or developer recreation

================================================================================
EXAMPLE SCRIPT OUTPUT
================================================================================

Expected VuGen output (successful):
  JWT Library version: 1.0.0
  New token generated for VUser 1

Expected JWT token format:
  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.
  eyJpc3MiOiJsb2FkdGVzdC1zeXN0ZW0iLCJzdWIiOiJ1c2VyLTEiLCJhdWQiOiJh...
  .[base64url-encoded-signature]

PS256 token header always decodes to:
  {"alg":"PS256","typ":"JWT"}
  Base64URL: eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9

RS256 token header always decodes to:
  {"alg":"RS256","typ":"JWT"}
  Base64URL: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9

HS256 token header always decodes to:
  {"alg":"HS256","typ":"JWT"}
  Base64URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

================================================================================
REFERENCES
================================================================================

JWT Specification:        RFC 7519
JWS Algorithms:          RFC 7518
JWT Best Practices:      RFC 8725
RSA-PSS:                 RFC 8017
OpenSSL EVP Reference:   https://www.openssl.org/docs/man3.0/man3/EVP_DigestSign.html
LRE DevWeb SDK:          https://admhelp.microfocus.com/lrd/en/26.1/help/Content/DevWeb/DW-JS-SDK.htm
DevWeb Libraries:        https://admhelp.microfocus.com/lrd/en/26.1/help/Content/DevWeb/DW-libraries.htm
OpenSSL Windows:         https://slproweb.com/products/Win32OpenSSL.html
CMake Download:          https://cmake.org/download/

================================================================================
VERSION HISTORY
================================================================================

v1.0.0 (2026-02-18):
  - Initial release
  - Platforms: Windows 2022/2025 DLL + RedHat Linux SO
  - Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512
  - DevWeb: Pure JavaScript module (jwt-lib.js)
  - LRE: 2025.1 and 26.1
  - DevWeb Node.js: v22.11.0

================================================================================
```

---

## How to Use This Prompt

### To recreate the entire project:
Copy everything between the triple backticks above and paste it into
Claude Code, GitHub Copilot, or any other AI coding assistant.

### To extend with a new feature, prepend:
```
Based on the JWTTokenLib specification below, please add [your feature].
[paste the specification]
```

### To fix a bug, prepend:
```
Based on the JWTTokenLib specification below, please investigate and fix
[describe the bug]. Here are the relevant files: [paste file contents]
[paste the specification]
```

### Key files to share with the AI when extending:
- [include/jwtlib.h](include/jwtlib.h) — public API contract
- [src/jwt_core.h](src/jwt_core.h) — internal types and structure
- [src/jwt_core.c](src/jwt_core.c) — main pipeline logic
- [jwt-lib.js](jwt-lib.js) — DevWeb module
- This file (COMPLETE_PROMPT.md) — all design decisions

---

*Project: JWTTokenLib v1.0.0*
*Author: LoadRunner Performance Engineering Team*
*Date: 2026*
