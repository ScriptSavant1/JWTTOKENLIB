# JWTTokenLib - JWT Token Generation for LoadRunner Enterprise

High-performance JWT token generation library for LRE load tests.
Supports **WEB HTTP/HTML** (C) and **DevWeb** (JavaScript) protocols.

## Supported Algorithms

| Algorithm | Type | Priority | Use Case |
|-----------|------|----------|----------|
| **PS256** | RSA-PSS + SHA-256 | Primary | Most enterprise APIs |
| **RS256** | RSA PKCS#1 + SHA-256 | High | Legacy RSA APIs |
| **HS256** | HMAC-SHA-256 | High | Internal/microservice APIs |
| **ES256** | ECDSA P-256 | Medium | High-performance APIs |
| PS384, PS512 | RSA-PSS variants | Supported | - |
| RS384, RS512 | RSA PKCS#1 variants | Supported | - |
| HS384, HS512 | HMAC variants | Supported | - |
| ES384, ES512 | ECDSA variants | Supported | - |

## Quick Start

### WEB HTTP/HTML Protocol (C)

**Step 1: Deploy**
```
Windows: Copy JWTTokenLib.dll → C:\Program Files\LoadRunner\bin\
Linux:   Copy libJWTTokenLib.so → /opt/HP/LoadRunner/lib/
```

**Step 2: Place your private key**
```
YourScript/
  extras/
    private_key.pem     ← RSA private key for PS256/RS256
```

**Step 3: Add to VuGen script**

*globals.h:*
```c
#include <time.h>

// JWT Library function declarations
int         JWT_Generate(const char* alg, const char* payload,
                         const char* key, char* out, int size);
int         JWT_Is_Token_Expiring(const char* token, int threshold_sec);
const char* JWT_Get_Error_Message(int error_code);
const char* JWT_Get_Version(void);
```

*vuser_init():*
```c
vuser_init() {
#ifdef WIN32
    lr_load_dll("JWTTokenLib.dll");
#else
    lr_load_dll("libJWTTokenLib.so");
#endif
    lr_log_message("JWT Library: %s", JWT_Get_Version());
    return 0;
}
```

*Action():*
```c
Action() {
    static char jwt_token[4096] = {0};
    char payload[2048];
    long ts = (long)time(NULL);

    // Generate token (or refresh if expiring soon)
    if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300)) {
        sprintf(payload,
            "{\"iss\":\"loadtest\",\"sub\":\"user-%d\","
            "\"exp\":%ld,\"iat\":%ld}",
            lr_get_vuser_id(), ts + 900, ts);

        int rc = JWT_Generate("PS256", payload,
                              "extras/private_key.pem",
                              jwt_token, sizeof(jwt_token));
        if (rc != 0) {
            lr_error_message("JWT Error: %s", JWT_Get_Error_Message(rc));
            return -1;
        }
        lr_save_string(jwt_token, "JWT_Token");
    }

    web_add_header("Authorization", lr_eval_string("Bearer {JWT_Token}"));
    web_url("API_Call", "URL=https://api.example.com/data", LAST);
    return 0;
}
```

---

### DevWeb Protocol (JavaScript)

**Step 1: Place files in script root folder**
```
YourDevWebScript/
  main.js              ← your script
  jwt-lib.js           ← copy from this project
  private_key.pem      ← RSA private key
```

**Step 2: Use in main.js**
```javascript
const jwt = require('./jwt-lib');

load.initialize('Setup', async function() {
    const fs = require('fs');
    global.privateKey = fs.readFileSync('./private_key.pem', 'utf8');
});

load.action('API_Transaction', async function() {
    const userId = load.config.user.userId;
    const now    = Math.floor(Date.now() / 1000);

    const token = jwt.generate({
        algorithm: 'PS256',
        payload: {
            iss: 'loadtest',
            sub: `user-${userId}`,
            exp: now + 900,
            iat: now
        },
        key: global.privateKey   // PEM content string
    });

    const response = await new load.WebRequest({
        url:     'https://api.example.com/data',
        method:  'GET',
        headers: { 'Authorization': `Bearer ${token}` }
    }).send();
});
```

---

## Key Input Options

All functions auto-detect key type — no configuration needed:

| Key Value | Auto-Detected As |
|-----------|-----------------|
| `"extras/private_key.pem"` | PEM file path |
| `"-----BEGIN PRIVATE KEY-----\n..."` | PEM content string |
| `"my-hmac-secret"` | HMAC secret (HS* only) |
| `"/path/to/cert.p12"` | PKCS#12 file |

**rts.yaml key parameter example:**
```c
// C - VuGen
JWT_Generate("PS256", payload, lr_eval_string("{PrivateKeyPEM}"), token, sizeof(token));
```
```javascript
// JavaScript - DevWeb
jwt.generate({ algorithm: 'PS256', payload: {...}, key: load.params.get('PrivateKeyPEM') });
```

---

## Token Refresh for Long Tests

Tokens with 15-minute expiry in a 2-hour load test:

**VuGen (C):**
```c
// At top of Action():
if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300)) {
    // Regenerate - less than 5 minutes remaining
    JWT_Generate("PS256", payload, key, jwt_token, sizeof(jwt_token));
}
```

**DevWeb (JS):**
```javascript
if (!global.token || jwt.isExpiring(global.token, 300)) {
    global.token = jwt.generate({ ... });
}
```

---

## Generate Keys

**RSA keys (for PS256, RS256):**
```bash
# Private key - 2048-bit minimum, 4096-bit recommended
openssl genrsa -out private_key.pem 2048

# Extract public key (for verification)
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

**ECDSA keys (for ES256):**
```bash
openssl ecparam -genkey -name prime256v1 -noout -out ec_private_key.pem
openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem
```

**HMAC secret (for HS256):**
```bash
openssl rand -base64 32 > hmac_secret.txt
```

---

## Build from Source

### Windows (Visual Studio 2026)

1. Install [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) to `C:\Program Files\OpenSSL-Win64\`
2. Install CMake 3.15+
3. Open Developer Command Prompt for VS 2026:

```powershell
mkdir build; cd build
cmake .. -G "Visual Studio 18 2026" -A x64 `
         -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
cmake --build . --config Release
```

Output: `build\bin\Release\JWTTokenLib.dll`

### Linux (RedHat / Amazon Linux)

```bash
# Install dependencies
sudo dnf install openssl-devel cmake gcc

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Output: `build/lib/libJWTTokenLib.so`

---

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `JWT_SUCCESS` | Success |
| -1 | `JWT_ERROR_INVALID_ALG` | Unknown algorithm |
| -2 | `JWT_ERROR_INVALID_KEY` | Invalid key/secret |
| -4 | `JWT_ERROR_BUFFER_SMALL` | Buffer too small (use 4096+) |
| -5 | `JWT_ERROR_SIGN_FAILED` | Signing failed (wrong key type?) |
| -6 | `JWT_ERROR_NULL_POINTER` | NULL argument |
| -7 | `JWT_ERROR_FILE_NOT_FOUND` | Key file not found |

Always check error codes and log them:
```c
if (rc != JWT_SUCCESS) {
    lr_error_message("JWT Error %d: %s", rc, JWT_Get_Error_Message(rc));
}
```

---

## Performance

Measured on 8-core server with 2048-bit RSA key:

| Algorithm | Estimated TPS | Notes |
|-----------|---------------|-------|
| HS256 | 500,000+ | HMAC is trivially fast |
| RS256 | 15,000-25,000 | PKCS#1 v1.5 |
| **PS256** | **8,000-12,000** | RSA-PSS (primary) |
| ES256 | 30,000+ | ECDSA is fast |

**For 100-1000 TPS load tests: all algorithms are well within capacity.**

---

## Deployment Checklist

### WEB HTTP/HTML on Windows LGs
- [ ] `JWTTokenLib.dll` → `C:\Program Files\LoadRunner\bin\`
- [ ] `private_key.pem` → script `extras/` folder

### WEB HTTP/HTML on Linux LGs
- [ ] `libJWTTokenLib.so` → `/opt/HP/LoadRunner/lib/`
- [ ] `private_key.pem` → script `extras/` folder
- [ ] Script uses `#ifdef WIN32` to load correct DLL/SO

### DevWeb (any OS)
- [ ] `jwt-lib.js` → DevWeb script root folder (same as `main.js`)
- [ ] `private_key.pem` → DevWeb script root folder

---

## Version

**1.0.0** - Initial release
LRE Compatibility: 2025.1, 26.1
Node.js Compatibility: v14+ (DevWeb uses v22.11.0)
