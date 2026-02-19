# JWTTokenLib - Complete User Guide
## For LoadRunner Enterprise (LRE) WEB HTTP/HTML and DevWeb Protocols

> **Who is this guide for?**
> This guide is written for anyone — even if you have never compiled a C library before.
> Follow each step exactly as shown. Every command you need to type is shown in a box.

---

## Table of Contents

1. [What Does This Library Do?](#1-what-does-this-library-do)
2. [What You Will Get After Setup](#2-what-you-will-get-after-setup)
3. [Setup on Windows (Build the DLL)](#3-setup-on-windows-build-the-dll)
4. [Setup on Linux RedHat (Build the SO)](#4-setup-on-linux-redhat-build-the-so)
5. [Deploy to LoadRunner](#5-deploy-to-loadrunner)
6. [Using in VuGen WEB HTTP/HTML Scripts](#6-using-in-vugen-web-httphtml-scripts)
7. [Using in DevWeb Scripts](#7-using-in-devweb-scripts)
8. [Generate Your Private Key](#8-generate-your-private-key)
9. [Verify Everything Works](#9-verify-everything-works)
10. [Quick Reference Card](#10-quick-reference-card)

---

## 1. What Does This Library Do?

When your application requires a JWT (JSON Web Token) to authenticate API calls during load tests, this library generates that token for you with **one simple function call**.

**Before this library:**
- Users had to write complex JavaScript code
- jsrassign.js was slow and could not handle high load
- Every team had a different approach

**After this library:**
```c
// WEB HTTP/HTML - this is ALL you need to add to your script
char token[4096];
JWT_Generate("PS256", payload, "extras/private_key.pem", token, sizeof(token));
```
```javascript
// DevWeb - this is ALL you need
const token = jwt.generate({ algorithm: 'PS256', payload: {...}, keyPath: './private_key.pem' });
```

---

## 2. What You Will Get After Setup

After completing this guide, you will have:

| File | Where it goes | Used by |
|------|--------------|---------|
| `JWTTokenLib.dll` | LoadRunner `bin\` folder (Windows LG) | WEB HTTP/HTML scripts on Windows |
| `libJWTTokenLib.so` | LoadRunner `lib/` folder (Linux LG) | WEB HTTP/HTML scripts on Linux |
| `jwt-lib.js` | Inside each DevWeb script folder | DevWeb scripts |

**For your script:**
- A private key file (`private_key.pem`) that you generate once and reuse

---

## 3. Setup on Windows (Build the DLL)

> **Important:** Do this on a Windows PC with internet access.
> You do NOT need to do this on the Load Generator itself.
> You build the DLL once, then copy it everywhere.

---

### Step 3.1 — Install Visual Studio 2026 (Build Tools)

1. Open your browser and go to:
   `https://visualstudio.microsoft.com/downloads/`

2. Scroll down to find **"Build Tools for Visual Studio 2026"** and click **Download**

3. Run the downloaded installer (`vs_BuildTools.exe`)

4. On the **Workloads** screen, tick:
   - ☑ **Desktop development with C++**

5. Click **Install** (this may take 10–20 minutes)

6. When done, restart your computer

> **How to check it worked:** Press the Windows key, search for
> `Developer Command Prompt for VS 2026` — if you see it, installation succeeded.

---

### Step 3.2 — Install CMake

1. Open your browser and go to:
   `https://cmake.org/download/`

2. Under **Binary distributions**, find the **Windows x64 Installer** row and click it

3. Run the downloaded installer (`cmake-X.XX.X-windows-x86_64.msi`)

4. On the **Install Options** page, select:
   - ☑ **Add CMake to the system PATH for all users**

5. Click **Install**

> **How to check it worked:** Open a new Command Prompt and type:
> ```
> cmake --version
> ```
> You should see something like: `cmake version 3.28.1`

---

### Step 3.3 — Install OpenSSL for Windows

1. Open your browser and go to:
   `https://slproweb.com/products/Win32OpenSSL.html`

2. Find the row **Win64 OpenSSL v3.x.x** (NOT the "Light" version) and click the `.msi` link

3. Run the downloaded installer

4. On the installation path screen, keep the default:
   ```
   C:\Program Files\OpenSSL-Win64
   ```

5. On the next screen, select:
   - ☑ **Copy OpenSSL DLLs to the Windows system directory**

6. Click **Install**

> **How to check it worked:** Open a new PowerShell and type:
> ```powershell
> & "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version
> ```
> You should see: `OpenSSL 3.x.x ...`

---

### Step 3.4 — Build the DLL

1. Press the Windows key and search for:
   **`Developer Command Prompt for VS 2026`**
   Right-click → **Run as administrator**

2. In the Developer Command Prompt, type these commands **one line at a time**:

```cmd
cd c:\Workspace\JWTTokenLib
```

```cmd
mkdir build
```

```cmd
cd build
```

```cmd
cmake .. -G "Visual Studio 18 2026" -A x64 -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
```

> Wait for CMake to finish. You should see lines ending with `-- Build files have been written to...`

```cmd
cmake --build . --config Release
```

> Wait for the build to complete. This takes 1–3 minutes.
> You should see `Build succeeded.` at the end.

3. When complete, your DLL is here:
   ```
   c:\Workspace\JWTTokenLib\build\bin\Release\JWTTokenLib.dll
   ```

> **Something went wrong?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → "Build Issues (Windows)"

---

### Step 3.5 — Run the Test (Windows)

First, generate a test key:

```cmd
cd c:\Workspace\JWTTokenLib
```

```cmd
mkdir tests\keys
```

```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out tests\keys\test_rsa_private.pem 2048
```

Now run the test:

```cmd
build\bin\Release\test_jwt.exe
```

You should see output like:
```
[PASS] JWT_Get_Version returns non-empty
[PASS] PS256 supported
[PASS] RS256 supported
[PASS] HS256 generate success
[PASS] PS256 generate success
...
Results: 20/20 passed
```

> If you see `[FAIL]` lines, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 4. Setup on Linux RedHat (Build the SO)

> **Do this on a RedHat / Amazon Linux server that has internet access.**
> This is typically done by a DevOps or infrastructure engineer.

---

### Step 4.1 — Install Dependencies

```bash
sudo dnf install -y gcc cmake make openssl-devel
```

> **Verify:**
> ```bash
> gcc --version
> cmake --version
> openssl version
> ```

---

### Step 4.2 — Build the Shared Library

```bash
cd /path/to/JWTTokenLib
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

When complete, your library is here:
```
build/lib/libJWTTokenLib.so
```

---

### Step 4.3 — Run the Test (Linux)

```bash
# Generate a test key
mkdir -p tests/keys
openssl genrsa -out tests/keys/test_rsa_private.pem 2048

# Run tests
./build/bin/test_jwt
```

You should see `Results: XX/XX passed`.

---

## 5. Deploy to LoadRunner

### Windows Load Generators

Copy the DLL to **every Windows Load Generator**:

```
Source:      c:\Workspace\JWTTokenLib\build\bin\Release\JWTTokenLib.dll

Destination: C:\Program Files\LoadRunner\bin\JWTTokenLib.dll
             (or wherever LoadRunner is installed on your LG)
```

**How to copy to a remote LG:**
```
\\LoadGen01\C$\Program Files\LoadRunner\bin\
\\LoadGen02\C$\Program Files\LoadRunner\bin\
```

> **Important:** You only need `JWTTokenLib.dll` — no other files.
> The DLL is self-contained (OpenSSL is built inside it).

---

### Linux Load Generators

Copy the library to **every Linux Load Generator**:

```bash
# From your build machine:
scp build/lib/libJWTTokenLib.so user@loadgen01:/opt/HP/LoadRunner/lib/
scp build/lib/libJWTTokenLib.so user@loadgen02:/opt/HP/LoadRunner/lib/
```

> **Note:** The exact LoadRunner path on Linux may vary.
> Common paths:
> - `/opt/HP/LoadRunner/lib/`
> - `/opt/MicroFocus/LoadRunner/lib/`
> Ask your LRE administrator for the correct path.

---

## 6. Using in VuGen WEB HTTP/HTML Scripts

### Step 6.1 — Prepare Your Private Key

If you do not have a private key yet, generate one:

**On Windows (PowerShell):**
```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out private_key.pem 2048
```

**On Linux:**
```bash
openssl genrsa -out private_key.pem 2048
```

> Keep `private_key.pem` safe — this is your signing key.
> Share it only with the application team that set up the JWT validation.

---

### Step 6.2 — Add Key to Your Script

In VuGen, in your script's **extras** folder, place your key file:

```
YourScript/
  Action.c
  vuser_init.c
  vuser_end.c
  globals.h
  extras/
    private_key.pem    ← PUT YOUR KEY HERE
```

To add the extras folder in VuGen:
- Right-click your script in VuGen
- Click **Add File to Script**
- Browse to your `private_key.pem`
- It will be placed in the `extras` folder automatically

---

### Step 6.3 — Update globals.h

Open `globals.h` in VuGen and add these lines at the **top** of the file:

```c
#include <time.h>

/* JWT Library function declarations */
int         JWT_Generate(const char* alg, const char* payload,
                         const char* key, char* out, int size);
int         JWT_Is_Token_Expiring(const char* token, int threshold_seconds);
const char* JWT_Get_Error_Message(int error_code);
const char* JWT_Get_Version(void);
int         JWT_Is_Algorithm_Supported(const char* algorithm);
```

---

### Step 6.4 — Update vuser_init.c

Open `vuser_init.c` and add the DLL loading code:

```c
vuser_init()
{
    /* Load JWT library - do this ONCE per VUser at startup */
#ifdef WIN32
    lr_load_dll("JWTTokenLib.dll");
#else
    lr_load_dll("libJWTTokenLib.so");
#endif

    /* Confirm library loaded - check in VuGen output */
    lr_log_message("JWT Library version: %s", JWT_Get_Version());

    return 0;
}
```

---

### Step 6.5 — Update Action.c

Here is a complete working example. Copy and adapt for your script:

```c
Action()
{
    /* Token stored between iterations (auto-refreshes when near expiry) */
    static char jwt_token[4096] = {0};

    char  payload[2048];
    int   vuser_id    = lr_get_vuser_id();
    long  current_ts  = (long)time(NULL);
    long  expire_ts   = current_ts + 900;  /* Token valid for 15 minutes */
    int   rc;

    /* -------------------------------------------------------
     * Generate token if first time OR if expiring in < 5 min
     * This handles long test runs (2+ hours) automatically
     * ------------------------------------------------------- */
    if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300))
    {
        /* Build your payload - customize claims as needed */
        sprintf(payload,
            "{"
            "\"iss\":\"loadtest-system\","
            "\"sub\":\"user-%d\","
            "\"aud\":\"api.yourcompany.com\","
            "\"exp\":%ld,"
            "\"iat\":%ld,"
            "\"jti\":\"req-%d-%ld\","
            "\"userId\":\"USER%05d\","
            "\"role\":\"customer\""
            "}",
            vuser_id, expire_ts, current_ts,
            vuser_id, current_ts, vuser_id
        );

        /* Generate the JWT token */
        rc = JWT_Generate(
            "PS256",                     /* Algorithm - change if needed */
            payload,                     /* Your payload JSON */
            "extras/private_key.pem",    /* Key file location */
            jwt_token,                   /* Output buffer */
            sizeof(jwt_token)            /* Buffer size */
        );

        /* Check for errors */
        if (rc != 0) {
            lr_error_message("JWT Error %d: %s", rc, JWT_Get_Error_Message(rc));
            return -1;
        }

        /* Save as LR parameter for use with lr_eval_string */
        lr_save_string(jwt_token, "JWT_Token");
        lr_log_message("New token generated for VUser %d", vuser_id);
    }

    /* -------------------------------------------------------
     * Add Authorization header and make your API call
     * ------------------------------------------------------- */
    web_add_header("Authorization", lr_eval_string("Bearer {JWT_Token}"));
    web_add_header("Content-Type",  "application/json");

    web_url("Your_API_Call",
        "URL=https://api.yourcompany.com/v1/endpoint",
        "Method=GET",
        LAST);

    return 0;
}
```

---

### Step 6.6 — Using rts.yaml Key Instead of File

If your team prefers to store the key in `rts.yaml` (not as a file):

**In rts.yaml:**
```yaml
Parameters:
  PrivateKeyPEM:
    Type: Table
    Values:
      - |-
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...
        (full PEM content here)
        -----END PRIVATE KEY-----
```

**In Action.c** (replace the `JWT_Generate` call):
```c
rc = JWT_Generate(
    "PS256",
    payload,
    lr_eval_string("{PrivateKeyPEM}"),   /* Key from rts.yaml */
    jwt_token,
    sizeof(jwt_token)
);
```

> The library automatically detects PEM content vs file path — no code changes needed.

---

### Step 6.7 — Algorithm Quick Reference

Change `"PS256"` in your `JWT_Generate` call to match what your application expects:

| Algorithm | When to use |
|-----------|-------------|
| `"PS256"` | RSA-PSS with SHA-256 — most common in enterprise APIs |
| `"RS256"` | RSA PKCS#1 v1.5 — used by some older APIs |
| `"HS256"` | HMAC secret — used for internal/microservice tokens |
| `"ES256"` | ECDSA — used by some cloud APIs |

> Not sure which to use? Ask your application development team.

---

## 7. Using in DevWeb Scripts

### Step 7.1 — Prepare Script Folder

Your DevWeb script folder should look like this:

```
YourDevWebScript/
  main.js              ← your script (already exists)
  jwt-lib.js           ← COPY from c:\Workspace\JWTTokenLib\jwt-lib.js
  private_key.pem      ← your RSA private key
```

**Copy jwt-lib.js:**
- Source: `c:\Workspace\JWTTokenLib\jwt-lib.js`
- Destination: Your DevWeb script root folder (same level as `main.js`)

**Copy private_key.pem:**
- Place your `private_key.pem` in the same folder as `main.js`

---

### Step 7.2 — Complete DevWeb Script Example

Replace the content of your `main.js` with this template:

```javascript
'use strict';

/* Load the JWT library (must be in same folder as this file) */
const jwt = require('./jwt-lib');

/* ============================================================
 * INITIALIZE - runs ONCE before the load test starts
 * ============================================================ */
load.initialize('Setup', async function() {
    /* Load your private key once - shared across all iterations */
    const fs = require('fs');
    global.privateKey = fs.readFileSync('./private_key.pem', 'utf8');

    /* OR: use rts.yaml parameter */
    /* global.privateKey = load.params.get('PrivateKeyPEM'); */

    load.log(`JWT Library ready: ${jwt.getVersion()}`);
});

/* ============================================================
 * ACTION - runs for EACH virtual user iteration
 * ============================================================ */
load.action('API_Transaction', async function() {
    const userId = load.config.user.userId;
    const now    = Math.floor(Date.now() / 1000);

    /* Generate token (or refresh if expiring in < 5 minutes) */
    if (!global.myToken || jwt.isExpiring(global.myToken, 300)) {
        global.myToken = jwt.generate({
            algorithm: 'PS256',             /* Change algorithm if needed */

            payload: {
                iss: 'loadtest-system',
                sub: `user-${userId}`,      /* Unique per VUser */
                aud: 'api.yourcompany.com',
                exp: now + 900,             /* Expires in 15 minutes */
                iat: now,
                jti: `req-${userId}-${now}`,
                userId: `USER${String(userId).padStart(5, '0')}`,
                role:   'customer'
            },

            key: global.privateKey          /* PEM content from initialize */
            /* OR: keyPath: './private_key.pem'  (reads file each time) */
        });

        load.log(`Token generated for user ${userId}`);
    }

    /* Make your API call with the token */
    const response = await new load.WebRequest({
        id:     'API_Get_Data',
        url:    'https://api.yourcompany.com/v1/endpoint',
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${global.myToken}`,
            'Content-Type':  'application/json'
        }
    }).send();

    load.log(`Response status: ${response.status}`);
});

/* ============================================================
 * FINALIZE - runs ONCE after the load test ends
 * ============================================================ */
load.finalize('Teardown', async function() {
    load.log('Test complete.');
});
```

---

### Step 7.3 — Test DevWeb Script Locally

Before running in LRE, test from command line:

```cmd
node tests\test_devweb.js
```

You should see: `Results: XX/XX passed`

---

## 8. Generate Your Private Key

> **Do this once. Keep the key file secure. Share only with your LRE admin.**

### For PS256 or RS256 (RSA key):

**Windows (PowerShell):**
```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out private_key.pem 2048
```

**Linux:**
```bash
openssl genrsa -out private_key.pem 2048
```

This creates a 2048-bit RSA private key.
For higher security, use 4096-bit (slower to sign):
```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out private_key.pem 4096
```

---

### For ES256 (ECDSA key):

**Windows (PowerShell):**
```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" ecparam -genkey -name prime256v1 -noout -out ec_private_key.pem
```

**Linux:**
```bash
openssl ecparam -genkey -name prime256v1 -noout -out ec_private_key.pem
```

---

### For HS256 (HMAC secret):

No key file needed — just use any string as your secret:
```c
JWT_Generate("HS256", payload, "my-secret-string-here", token, sizeof(token));
```

---

### Share the Public Key with Your Application Team

Your application needs the **public key** to verify tokens.
Generate the public key from your private key:

**Windows (PowerShell):**
```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" rsa -in private_key.pem -pubout -out public_key.pem
```

**Linux:**
```bash
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

Share `public_key.pem` with your application team. **Never share the private key.**

---

## 9. Verify Everything Works

### Check Token Format

After generating a token, it should look like this (three parts separated by dots):
```
eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2FkdGVzdC...
^--- HEADER ---^                        ^------- PAYLOAD --------^
```

**Part 1** (before first dot): Always starts with `eyJ` for JWT tokens.
**Part 2** (between dots): Your payload, encoded.
**Part 3** (after second dot): The cryptographic signature.

### Inspect Your Token Online

1. Copy your generated token (the full string with dots)
2. Open browser, go to: `https://jwt.io`
3. Paste the token in the left box
4. You should see your claims (sub, exp, iat, etc.) on the right

> **This only checks the format, not the signature** — that is validated by your API.

### Check VuGen Replay Output

In VuGen replay, look for these lines in the output:
```
JWT Library version: 1.0.0
New token generated for VUser 1
```

If you see `JWT Error` instead, copy the error message and check [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 10. Quick Reference Card

### VuGen Script Checklist

- [ ] `JWTTokenLib.dll` copied to LoadRunner `bin\` on Windows LGs
- [ ] `libJWTTokenLib.so` copied to LoadRunner `lib/` on Linux LGs
- [ ] `private_key.pem` in script `extras/` folder
- [ ] Function declarations added to `globals.h`
- [ ] `lr_load_dll()` called in `vuser_init()`
- [ ] `JWT_Generate()` called in `Action()`
- [ ] Script replays successfully in VuGen before uploading to LRE

### DevWeb Script Checklist

- [ ] `jwt-lib.js` copied to DevWeb script root folder
- [ ] `private_key.pem` in DevWeb script root folder
- [ ] `require('./jwt-lib')` at top of `main.js`
- [ ] Key loaded in `load.initialize()`
- [ ] Token generated and used in `load.action()`
- [ ] Script tested locally with `node tests/test_devweb.js`

### Function Reference

**C (VuGen WEB HTTP/HTML):**

```c
/* Generate a JWT token */
int JWT_Generate(
    const char* algorithm,     /* "PS256", "RS256", "HS256", "ES256" */
    const char* payload_json,  /* {"sub":"user1","exp":1234567890,...} */
    const char* key,           /* file path OR PEM string OR HMAC secret */
    char*       output,        /* char buffer[4096] */
    int         buffer_size    /* sizeof(buffer) */
);

/* Check if token needs refresh (use in long test runs) */
int JWT_Is_Token_Expiring(
    const char* token,         /* current token */
    int         threshold_sec  /* seconds before expiry to warn (e.g. 300) */
);
/* Returns: 1 = refresh needed, 0 = still valid, -1 = no exp claim */

/* Get error description */
const char* JWT_Get_Error_Message(int error_code);
```

**JavaScript (DevWeb):**

```javascript
/* Generate a JWT token */
const token = jwt.generate({
    algorithm: 'PS256',           // required
    payload:   { sub: 'user1' },  // required - object (not string)
    keyPath:   './private_key.pem' // OR: key: pemString, OR: secret: 'hmac'
});

/* Check if token needs refresh */
const needsRefresh = jwt.isExpiring(token, 300); // true/false

/* Decode token payload (no verification) */
const payload = jwt.decode(token);
```

---

## Getting Help

| Issue | Where to look |
|-------|--------------|
| Build errors | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → Build Issues |
| Runtime errors in VuGen | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → WEB HTTP/HTML Issues |
| DevWeb errors | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → DevWeb Issues |
| API returning 401 | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → Token generated but API returns 401 |
| Full API reference | [README.md](README.md) |

---

*JWTTokenLib v1.0.0 | LRE 2025.1 / 26.1 | Windows 2022/2025 + RedHat Linux*
