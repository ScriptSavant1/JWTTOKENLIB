# JWTTokenLib - Troubleshooting Guide

## WEB HTTP/HTML Protocol Issues

---

### Error: `JWT_Generate` function not found / lr_load_dll fails

**Symptom:** VuGen reports "function not declared" or lr_load_dll returns error.

**Cause 1: DLL not in correct location**
```
Fix: Copy JWTTokenLib.dll to C:\Program Files\LoadRunner\bin\
     (not to the script folder)
```

**Cause 2: Missing function declarations in globals.h**
```c
// Add these to globals.h:
int         JWT_Generate(const char* alg, const char* payload,
                         const char* key, char* out, int size);
int         JWT_Is_Token_Expiring(const char* token, int threshold);
const char* JWT_Get_Error_Message(int error_code);
const char* JWT_Get_Version(void);
int         JWT_Is_Algorithm_Supported(const char* algorithm);
```

**Cause 3: Linux LG loading wrong file name**
```c
// Use platform conditional:
#ifdef WIN32
    lr_load_dll("JWTTokenLib.dll");
#else
    lr_load_dll("libJWTTokenLib.so");
#endif
```

---

### Error code -7: `JWT_ERROR_FILE_NOT_FOUND`

**Symptom:** `JWT_Get_Error_Message(-7)` returns "Key file not found"

**Cause:** The PEM file path is wrong or the file is not deployed to the Load Generator.

**Fix 1: Check relative path**
VuGen scripts execute with CWD = the script folder.
Your extras/ folder is a subfolder of the script:
```c
// Correct:
JWT_Generate("PS256", payload, "extras/private_key.pem", token, sizeof(token));

// Wrong (absolute path won't work on all LGs):
JWT_Generate("PS256", payload, "C:/keys/private_key.pem", token, sizeof(token));
```

**Fix 2: Verify file is on all Load Generators**
```
For each LG, verify file exists at:
  Windows: \\LoadGenXX\C$\path\to\script\extras\private_key.pem
  Linux:   /path/to/script/extras/private_key.pem
```

**Fix 3: Use rts.yaml parameter instead of file**
Store the full PEM content in rts.yaml and pass it as a parameter:
```c
JWT_Generate("PS256", payload, lr_eval_string("{PrivateKeyPEM}"), token, sizeof(token));
```
In rts.yaml:
```yaml
parameters:
  PrivateKeyPEM: |
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqh...
    -----END PRIVATE KEY-----
```

---

### Error code -5: `JWT_ERROR_SIGN_FAILED`

**Symptom:** Token generation fails with "Cryptographic signing failed"

**Cause 1: Wrong key type for algorithm**
- PS256/RS256 need an RSA private key
- ES256 needs an EC private key
- HS256 needs a plain string secret (not a file)

**Cause 2: Corrupted PEM file**
Verify the key is valid:
```bash
openssl rsa -in private_key.pem -check     # RSA key
openssl ec  -in ec_private_key.pem -check  # EC key
```

**Cause 3: Public key passed instead of private key**
```bash
# Check file type - should say PRIVATE KEY, not PUBLIC KEY:
head -1 private_key.pem
# Correct:   -----BEGIN PRIVATE KEY-----
# Wrong:     -----BEGIN PUBLIC KEY-----
```

**Cause 4: rts.yaml line ending issues**
If PEM content from rts.yaml has Windows line endings (\r\n),
OpenSSL may fail to parse it. Ensure the PEM uses Unix line endings (\n).

---

### Error code -4: `JWT_ERROR_BUFFER_SMALL`

**Symptom:** Token is truncated or buffer error

**Fix:** Increase the output buffer size. For large payloads, 8192 bytes:
```c
char jwt_token[8192];  // Increase from 4096 if payload is large
JWT_Generate("PS256", payload, key, jwt_token, sizeof(jwt_token));
```

---

### Error code -1: `JWT_ERROR_INVALID_ALG`

**Symptom:** "Unsupported algorithm"

**Common mistakes:**
```c
// Wrong - SHA256 is not a JWT algorithm name:
JWT_Generate("SHA256", ...)     // WRONG
JWT_Generate("RSA-PSS", ...)    // WRONG
JWT_Generate("HMAC", ...)       // WRONG

// Correct JWT algorithm names:
JWT_Generate("PS256", ...)      // RSA-PSS with SHA-256
JWT_Generate("RS256", ...)      // RSA PKCS#1 v1.5 with SHA-256
JWT_Generate("HS256", ...)      // HMAC with SHA-256
JWT_Generate("ES256", ...)      // ECDSA with P-256
```

---

### Token generated but API returns 401 Unauthorized

**Cause 1: Wrong algorithm for the API**
Verify with the application team which algorithm the API expects.
Try each: PS256, RS256, HS256.

**Cause 2: Wrong private key**
The private key must match the public key registered with the API.
Verify: `openssl rsa -in private_key.pem -pubout | diff - public_key.pem`

**Cause 3: Clock skew**
The `iat` (issued at) or `exp` (expiry) values use `time(NULL)`.
If the Load Generator clock is skewed, the token may be rejected.
```c
// Add a buffer: set iat slightly in the past
long ts = (long)time(NULL) - 5;  // 5 seconds in the past
long exp = ts + 900;
```

**Cause 4: Wrong audience (`aud`) claim**
Some APIs validate the `aud` claim strictly. Verify with the API team.

**Cause 5: Missing required custom claims**
Check if the API requires additional claims (e.g., `tenantId`, `scope`).

---

## DevWeb Protocol Issues

---

### `require('./jwt-lib')` throws "MODULE_NOT_FOUND"

**Fix:** Ensure `jwt-lib.js` is in the **same folder** as `main.js` (script root).
```
YourScript/
  main.js        ← your DevWeb script
  jwt-lib.js     ← must be HERE, not in a subfolder
  private_key.pem
```

---

### DevWeb: `jwt.generate()` throws "Cannot read properties of undefined"

**Cause:** Missing required options field.

**Fix:** Check all required fields are present:
```javascript
const token = jwt.generate({
    algorithm: 'PS256',   // required
    payload:   { ... },   // required - must be an object
    keyPath:   './private_key.pem'  // required for PS256/RS256/ES256
    // OR: key: pemContentString
    // OR: secret: 'string' for HS256
});
```

---

### DevWeb: Private key file not found

**Symptom:** `Error: ENOENT: no such file or directory`

**Fix:** The key file path is relative to the script root folder.
Use `./private_key.pem` (not `extras/private_key.pem` like in WEB HTTP/HTML).

```javascript
// DevWeb - key in script root folder:
keyPath: './private_key.pem'

// NOT this (extras/ doesn't apply to DevWeb):
keyPath: 'extras/private_key.pem'
```

---

### DevWeb: `TypeError: Invalid key or IV` or `error:09091064`

**Cause:** PEM content from `load.params.get()` has extra whitespace or encoding issues.

**Fix:**
```javascript
// Trim the key content:
const keyContent = load.params.get('PrivateKeyPEM').trim();
const token = jwt.generate({ algorithm: 'PS256', payload: {...}, key: keyContent });
```

---

### DevWeb: Token generated but ECDSA signature fails to verify

**Cause:** The DER→R||S conversion in `jwt-lib.js` handles most cases, but
some EC keys produce edge case signatures.

**Debug:** Check the signature length:
```javascript
const parts = token.split('.');
const sigB64 = parts[2];
const sigBytes = Buffer.from(sigB64.replace(/-/g,'+').replace(/_/g,'/'), 'base64');
load.log(`ES256 signature length: ${sigBytes.length} bytes (expected 64)`);
```

---

## Build Issues (Windows)

---

### CMake error: "Could not find OpenSSL"

```powershell
cmake .. -G "Visual Studio 18 2026" -A x64 `
         -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
```

If OpenSSL is installed in a non-default location, set OPENSSL_ROOT_DIR accordingly.

---

### MSVC error: "unresolved external symbol __imp_JWT_Generate"

This means the test program can't find the DLL import library.
Ensure CMake is linking against the correct .lib file:
```
build\lib\Release\JWTTokenLib.lib  ← import library for DLL
build\bin\Release\JWTTokenLib.dll  ← actual DLL
```

---

### OpenSSL static link error: "cannot open file 'libssl.lib'"

Static OpenSSL on Windows requires the full static build.
Download: https://slproweb.com/products/Win32OpenSSL.html
Install the full version, not the light version.

For static libs, look for:
```
C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\libssl.lib
C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\libcrypto.lib
```

---

## Build Issues (Linux)

---

### "openssl/evp.h: No such file or directory"

```bash
# RedHat / Amazon Linux:
sudo dnf install openssl-devel

# Ubuntu/Debian:
sudo apt-get install libssl-dev
```

---

### "libJWTTokenLib.so: cannot open shared object file"

```bash
# Add library path:
export LD_LIBRARY_PATH=/opt/HP/LoadRunner/lib:$LD_LIBRARY_PATH

# Or add to /etc/ld.so.conf.d/:
echo "/opt/HP/LoadRunner/lib" | sudo tee /etc/ld.so.conf.d/loadrunner.conf
sudo ldconfig
```

---

## General Debugging Tips

**Enable verbose logging in VuGen:**
```c
lr_log_message("Algorithm: PS256, Key: %s", "extras/private_key.pem");
int rc = JWT_Generate("PS256", payload, key, token, sizeof(token));
lr_log_message("JWT_Generate rc=%d, token_len=%d", rc, (int)strlen(token));
if (rc != 0) lr_error_message("JWT Error: %s", JWT_Get_Error_Message(rc));
```

**Verify token online:** Paste your token at https://jwt.io to inspect header, payload, and check the structure (signature verification requires the public key).

**Check token structure (minimum viable payload):**
```c
// Start simple, add claims one by one:
JWT_Generate("HS256", "{\"sub\":\"test\"}", "test-secret", token, sizeof(token));
```
