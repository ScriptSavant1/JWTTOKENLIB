# JWTTokenLib — Distributable Files

Download the file(s) you need from this folder. No build tools required.

---

## WEB HTTP/HTML Protocol (VuGen C scripts)

| OS | File | Copy to Load Generator |
|----|------|----------------------|
| **Windows** | `windows/x64/JWTTokenLib.dll` | `C:\Program Files\LoadRunner\bin\` |
| **Linux** | `linux/x64/libJWTTokenLib.so` | `/opt/HP/LoadRunner/lib/` |

> The Windows DLL has OpenSSL statically linked inside — no other files needed.
> The Linux SO links against the system OpenSSL already installed on RedHat.

---

## DevWeb Protocol (JavaScript scripts)

| File | Copy to |
|------|---------|
| `jwt-lib.js` | Your DevWeb script root folder (same level as `main.js`) |

> No DLL or SO needed for DevWeb. Pure JavaScript using Node.js built-in crypto.

---

## Linux SO Status

`linux/x64/libJWTTokenLib.so` must be built on a RedHat/Amazon Linux machine:
```bash
sudo dnf install -y gcc cmake make openssl-devel
cd JWTTokenLib
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
# Output: build/lib/libJWTTokenLib.so
```
Copy the built `.so` file into `dist/linux/x64/` and commit it.

---

## Version

| File | Version | Built with | Date |
|------|---------|-----------|------|
| `windows/x64/JWTTokenLib.dll` | 1.0.0 | VS2026 + OpenSSL 3.6.1 | 2026-02-19 |
| `jwt-lib.js` | 1.0.0 | Node.js v22.11.0 compatible | 2026-02-19 |
