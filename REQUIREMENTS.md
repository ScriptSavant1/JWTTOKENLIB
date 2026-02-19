# JWTTokenLib — Requirements & Prerequisites

## Overview

This document lists everything required to **build**, **deploy**, and **use** JWTTokenLib
in your LoadRunner Enterprise environment.

---

## 1. Build Machine Requirements

> The build machine is where you compile the library.
> This is a **one-time setup** — you build once, then deploy everywhere.

### Windows Build Machine

| Requirement | Minimum | Recommended | Download |
|-------------|---------|-------------|----------|
| Operating System | Windows 10 x64 | Windows 11 / Server 2022 | - |
| Visual Studio Build Tools | 2019 | **2022** | https://visualstudio.microsoft.com/downloads/ |
| VS Workload | Desktop development with C++ | Same | (select during VS install) |
| CMake | 3.15 | **3.28+** | https://cmake.org/download/ |
| OpenSSL | 3.0.x | **3.3.x** | https://slproweb.com/products/Win32OpenSSL.html |
| Disk space | 2 GB | 5 GB | - |
| RAM | 4 GB | 8 GB | - |

> **OpenSSL important:** Download the **full** installer (NOT the "Light" version).
> Install to default path: `C:\Program Files\OpenSSL-Win64\`

---

### Linux Build Machine (RedHat / Amazon Linux)

| Requirement | Minimum | Command to install |
|-------------|---------|-------------------|
| OS | RHEL 8 / Amazon Linux 2023 | - |
| GCC | 9.x | `sudo dnf install gcc` |
| CMake | 3.15 | `sudo dnf install cmake` |
| OpenSSL development headers | 3.x | `sudo dnf install openssl-devel` |
| make | any | `sudo dnf install make` |

**Single install command:**
```bash
sudo dnf install -y gcc cmake make openssl-devel
```

---

## 2. Load Generator Requirements

> These are the machines that run your load test VUsers.
> The compiled library files must be deployed here.

### Windows Load Generators

| Requirement | Details |
|-------------|---------|
| OS | Windows Server 2019 / 2022 / 2025 |
| LoadRunner Agent | Installed and configured |
| Required file | `JWTTokenLib.dll` in LoadRunner `bin\` folder |
| No other dependencies | DLL is self-contained (OpenSSL statically linked) |

**Where to copy the DLL:**
```
C:\Program Files\LoadRunner\bin\JWTTokenLib.dll
```
or wherever LoadRunner is installed on your LG.

---

### Linux Load Generators

| Requirement | Details |
|-------------|---------|
| OS | RedHat Enterprise Linux 8/9, Amazon Linux 2023 |
| LoadRunner Agent | Installed and configured |
| OpenSSL runtime | `openssl` package (usually pre-installed) |
| Required file | `libJWTTokenLib.so` in LoadRunner `lib/` folder |

**Where to copy the SO:**
```bash
/opt/HP/LoadRunner/lib/libJWTTokenLib.so
# OR (depending on LRE installation):
/opt/MicroFocus/LoadRunner/lib/libJWTTokenLib.so
```

**If OpenSSL is not installed:**
```bash
sudo dnf install openssl
```

---

## 3. LRE (LoadRunner Enterprise) Requirements

| Item | Requirement |
|------|-------------|
| LRE Version | 2025.1 or 26.1 |
| WEB HTTP/HTML protocol | VuGen with C language support |
| DevWeb protocol | LRE DevWeb with Node.js v22.11.0 (bundled in LRE 26.1) |
| LRE Controller | Any version compatible with LRE 2025.1 / 26.1 |
| Load Generator connectivity | LGs must be able to read script files (extras/ folder) |

---

## 4. VuGen Script Requirements

For **WEB HTTP/HTML** scripts using this library:

| Item | Requirement |
|------|-------------|
| Protocol | WEB HTTP/HTML (C language) |
| Script structure | `vuser_init.c`, `Action.c`, `globals.h` |
| Key file location | `extras/private_key.pem` in script folder |
| Output buffer size | Minimum 4096 bytes (`char token[4096]`) |
| `time.h` | Must be included in `globals.h` |

**Required function declarations in globals.h:**
```c
#include <time.h>
int         JWT_Generate(const char*, const char*, const char*, char*, int);
int         JWT_Is_Token_Expiring(const char*, int);
const char* JWT_Get_Error_Message(int);
const char* JWT_Get_Version(void);
int         JWT_Is_Algorithm_Supported(const char*);
```

---

## 5. DevWeb Script Requirements

For **DevWeb** scripts using this library:

| Item | Requirement |
|------|-------------|
| Protocol | DevWeb (JavaScript) |
| Node.js version | v14+ (LRE 26.1 bundles v22.11.0) |
| Required file in script root | `jwt-lib.js` |
| Key file location | Script root folder (same level as `main.js`) |
| External npm packages | **None required** — uses Node.js built-in `crypto` |

**No npm install needed.** The library uses only:
- `crypto` (built-in Node.js module)
- `fs` (built-in Node.js module)

---

## 6. Private Key Requirements

| Requirement | Details |
|-------------|---------|
| Key format | PEM (`.pem`) or PKCS#12 (`.p12` / `.pfx`) |
| Encryption | Unencrypted (no passphrase) |
| RSA key size | Minimum 2048-bit (4096-bit recommended for PS256/RS256) |
| EC curve (ES256) | P-256 (`prime256v1`) |
| EC curve (ES384) | P-384 (`secp384r1`) |
| EC curve (ES512) | P-521 (`secp521r1`) |
| HMAC secret | Any string (no file needed) |

> **JKS format is NOT supported.** If your key is in JKS format, convert it:
> ```bash
> keytool -importkeystore -srckeystore keystore.jks \
>         -destkeystore output.p12 -deststoretype PKCS12
> openssl pkcs12 -in output.p12 -nocerts -nodes -out private_key.pem
> ```

---

## 7. Supported JWT Algorithms

| Algorithm | Key Type Needed | Notes |
|-----------|----------------|-------|
| **PS256** | RSA private key (2048+ bit) | **Primary — most enterprise APIs** |
| PS384 | RSA private key | PS256 variant |
| PS512 | RSA private key | PS256 variant |
| **RS256** | RSA private key (2048+ bit) | Common in legacy APIs |
| RS384 | RSA private key | RS256 variant |
| RS512 | RSA private key | RS256 variant |
| **HS256** | HMAC secret string | Common for internal/microservices |
| HS384 | HMAC secret string | HS256 variant |
| HS512 | HMAC secret string | HS256 variant |
| ES256 | EC private key (P-256) | High-performance option |
| ES384 | EC private key (P-384) | ES256 variant |
| ES512 | EC private key (P-521) | ES256 variant |

---

## 8. Network and Security Requirements

| Item | Requirement |
|------|-------------|
| Outbound internet access | Only needed on build machine (to download dependencies) |
| LG to application server | Standard HTTPS (port 443) — no change from existing setup |
| Private key storage | Stored in script `extras/` folder or LRE parameter store |
| Private key security | Do not commit to source control; use LRE parameter store for production |

---

## 9. Compatibility Matrix

| Platform | Protocol | File | Status |
|----------|---------|------|--------|
| Windows 2022 LG | WEB HTTP/HTML | `JWTTokenLib.dll` | ✅ Supported |
| Windows 2025 LG | WEB HTTP/HTML | `JWTTokenLib.dll` | ✅ Supported |
| RedHat Linux 8/9 LG | WEB HTTP/HTML | `libJWTTokenLib.so` | ✅ Supported |
| Amazon Linux 2023 LG | WEB HTTP/HTML | `libJWTTokenLib.so` | ✅ Supported |
| LRE 2025.1 DevWeb | DevWeb | `jwt-lib.js` | ✅ Supported |
| LRE 26.1 DevWeb | DevWeb | `jwt-lib.js` | ✅ Supported |
| VuGen on Windows | WEB HTTP/HTML | Replay mode | ✅ Supported |
| LRE Controller | WEB HTTP/HTML | Load test execution | ✅ Supported |

---

## 10. What You Do NOT Need

| Item | Status | Reason |
|------|--------|--------|
| Node.js on Load Generator | ❌ Not needed for WEB HTTP/HTML | DLL is self-contained |
| OpenSSL DLLs alongside JWTTokenLib.dll | ❌ Not needed | Statically linked inside DLL |
| npm install for DevWeb | ❌ Not needed | Uses built-in Node.js crypto |
| Native .node addon for DevWeb | ❌ Not needed | Pure JavaScript module |
| Admin rights on LG (runtime) | ❌ Not needed | Just reading a DLL from bin/ |
| Password for private key | ❌ Not supported | Use unencrypted PEM keys |
| JKS format support | ❌ Not supported | Convert to PEM first |
| Internet access on LG | ❌ Not needed | All dependencies compiled in |
