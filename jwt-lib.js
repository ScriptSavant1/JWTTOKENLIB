/**
 * jwt-lib.js - JWT Token Generation for LoadRunner DevWeb Protocol
 * ================================================================
 *
 * Pure JavaScript module using Node.js built-in 'crypto' module.
 * NO external dependencies. NO npm install required.
 * NO native addon (.node) - just copy this file to your DevWeb script folder.
 *
 * Compatible with: Node.js v14+ (LRE DevWeb uses v22.11.0)
 * Algorithms:  PS256, PS384, PS512 (RSA-PSS)         ← primary
 *              RS256, RS384, RS512 (RSA PKCS#1 v1.5)
 *              HS256, HS384, HS512 (HMAC)
 *              ES256, ES384, ES512 (ECDSA)
 *
 * USAGE in DevWeb script (main.js):
 *   const jwt = require('./jwt-lib');
 *
 *   // Option 1: Key file in script root folder
 *   const token = jwt.generate({
 *       algorithm: 'PS256',
 *       payload: { sub: 'user1', exp: Math.floor(Date.now()/1000) + 3600 },
 *       keyPath: './private_key.pem'
 *   });
 *
 *   // Option 2: PEM content string (from rts.yaml parameter)
 *   const token = jwt.generate({
 *       algorithm: 'PS256',
 *       payload: { sub: 'user1', exp: Math.floor(Date.now()/1000) + 3600 },
 *       key: load.params.get('PrivateKeyPEM')
 *   });
 *
 *   // Option 3: HMAC secret
 *   const token = jwt.generate({
 *       algorithm: 'HS256',
 *       payload: { sub: 'user1', exp: Math.floor(Date.now()/1000) + 3600 },
 *       secret: 'my-secret-key'
 *   });
 *
 * ================================================================
 */

'use strict';

const crypto = require('crypto');
const fs     = require('fs');

const VERSION = '1.0.0';

/* ============================================================
 * Internal: Base64URL encoding / decoding
 * ============================================================ */
function base64urlEncode(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g,  '');
}

function base64urlDecode(str) {
    /* Re-add standard Base64 padding */
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4 !== 0) str += '=';
    return Buffer.from(str, 'base64');
}

/* ============================================================
 * Internal: Convert OpenSSL DER ECDSA signature → JWT R||S format
 *
 * OpenSSL crypto.sign() for EC keys returns ASN.1 DER:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *
 * JWT RFC 7518 §3.4 requires raw R||S concatenation,
 * each zero-padded to the curve's coordinate byte size.
 * ============================================================ */
function derToJwtEcdsa(derBuf, alg) {
    const curveSize = { ES256: 32, ES384: 48, ES512: 66 }[alg];
    if (!curveSize) throw new Error('Unknown ECDSA algorithm: ' + alg);

    let offset = 0;

    /* Skip SEQUENCE tag (0x30) and length */
    if (derBuf[offset++] !== 0x30) throw new Error('Invalid DER: expected SEQUENCE');
    /* Handle long-form length encoding */
    if (derBuf[offset] & 0x80) {
        offset += (derBuf[offset] & 0x7F) + 1;
    } else {
        offset++;
    }

    /* Read INTEGER r */
    if (derBuf[offset++] !== 0x02) throw new Error('Invalid DER: expected INTEGER for r');
    let rLen = derBuf[offset++];
    /* Strip leading zero byte (sign byte for positive BigInteger) */
    if (derBuf[offset] === 0x00) { offset++; rLen--; }
    const r = derBuf.slice(offset, offset + rLen);
    offset += rLen;

    /* Read INTEGER s */
    if (derBuf[offset++] !== 0x02) throw new Error('Invalid DER: expected INTEGER for s');
    let sLen = derBuf[offset++];
    /* Strip leading zero byte */
    if (derBuf[offset] === 0x00) { offset++; sLen--; }
    const s = derBuf.slice(offset, offset + sLen);

    /* Right-align r and s in their respective curveSize slots */
    const result = Buffer.alloc(curveSize * 2, 0);
    r.copy(result, curveSize - r.length);
    s.copy(result, curveSize * 2 - s.length);

    return result;
}

/* ============================================================
 * Internal: Load private key from path or string
 * Returns raw PEM/key material that Node.js crypto accepts.
 * ============================================================ */
function resolveKey(options) {
    if (options.keyPath) {
        /* Read PEM file from path (relative to script folder) */
        return fs.readFileSync(options.keyPath);
    }
    if (options.key) {
        /* Key passed as string (PEM content from rts.yaml parameter) */
        return options.key;
    }
    return null;
}

/* ============================================================
 * generate(options) - Generate a signed JWT token
 *
 * @param {Object} options
 *   algorithm {string}  - 'PS256', 'RS256', 'HS256', 'ES256', etc.
 *   payload   {Object}  - Claims object (will be JSON-stringified)
 *   keyPath   {string}  - Path to PEM file (relative to script root)
 *   key       {string}  - PEM content string (from rts.yaml param)
 *   secret    {string}  - HMAC secret (for HS* algorithms only)
 *   header    {Object}  - Optional extra header fields (e.g. {kid:'key-1'})
 *
 * @returns {string} Signed JWT token
 * @throws  {Error}  On invalid input or signing failure
 * ============================================================ */
function generate(options) {
    if (!options)           throw new Error('[jwt-lib] options object is required');
    if (!options.algorithm) throw new Error('[jwt-lib] algorithm is required');
    if (!options.payload)   throw new Error('[jwt-lib] payload object is required');

    const alg = options.algorithm.toUpperCase();

    /* --- Build header --- */
    const headerObj = Object.assign({ alg, typ: 'JWT' }, options.header || {});
    const headerB64 = base64urlEncode(Buffer.from(JSON.stringify(headerObj)));

    /* --- Build payload --- */
    const payloadB64 = base64urlEncode(Buffer.from(JSON.stringify(options.payload)));

    /* --- Signing input --- */
    const signingInput = `${headerB64}.${payloadB64}`;

    let signature;

    /* ---- HMAC algorithms: HS256 / HS384 / HS512 ---- */
    if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
        const secret = options.secret || options.key;
        if (!secret) {
            throw new Error('[jwt-lib] secret or key is required for HMAC algorithms');
        }
        const hashAlg = alg === 'HS256' ? 'sha256'
                      : alg === 'HS384' ? 'sha384'
                      :                   'sha512';
        signature = crypto.createHmac(hashAlg, secret)
                          .update(signingInput)
                          .digest();

    /* ---- RSA-PSS: PS256 / PS384 / PS512 ---- */
    } else if (alg === 'PS256' || alg === 'PS384' || alg === 'PS512') {
        const keyData = resolveKey(options);
        if (!keyData) throw new Error('[jwt-lib] keyPath or key is required for PS* algorithms');

        const hashAlg = alg === 'PS256' ? 'sha256'
                      : alg === 'PS384' ? 'sha384'
                      :                   'sha512';

        signature = crypto.sign(
            hashAlg,
            Buffer.from(signingInput),
            {
                key:        crypto.createPrivateKey(keyData),
                padding:    crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            }
        );

    /* ---- RSA PKCS#1 v1.5: RS256 / RS384 / RS512 ---- */
    } else if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512') {
        const keyData = resolveKey(options);
        if (!keyData) throw new Error('[jwt-lib] keyPath or key is required for RS* algorithms');

        const hashAlg = alg === 'RS256' ? 'sha256'
                      : alg === 'RS384' ? 'sha384'
                      :                   'sha512';

        signature = crypto.sign(
            hashAlg,
            Buffer.from(signingInput),
            {
                key:     crypto.createPrivateKey(keyData),
                padding: crypto.constants.RSA_PKCS1_PADDING
            }
        );

    /* ---- ECDSA: ES256 / ES384 / ES512 ---- */
    } else if (alg === 'ES256' || alg === 'ES384' || alg === 'ES512') {
        const keyData = resolveKey(options);
        if (!keyData) throw new Error('[jwt-lib] keyPath or key is required for ES* algorithms');

        const hashAlg = alg === 'ES256' ? 'sha256'
                      : alg === 'ES384' ? 'sha384'
                      :                   'sha512';

        /* Node.js returns DER format for EC - convert to JWT R||S format */
        const derSig  = crypto.sign(hashAlg, Buffer.from(signingInput),
                                    crypto.createPrivateKey(keyData));
        signature = derToJwtEcdsa(derSig, alg);

    } else {
        throw new Error(`[jwt-lib] Unsupported algorithm: ${alg}`);
    }

    return `${signingInput}.${base64urlEncode(signature)}`;
}

/* ============================================================
 * decode(token) - Decode payload WITHOUT signature verification
 *
 * @param  {string} token - JWT token string
 * @returns {Object} Decoded payload object
 * @throws  {Error}  On invalid token format
 * ============================================================ */
function decode(token) {
    if (!token || typeof token !== 'string') {
        throw new Error('[jwt-lib] token must be a string');
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('[jwt-lib] Invalid JWT format: expected 3 dot-separated parts');
    }
    return JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
}

/* ============================================================
 * isExpiring(token, thresholdSeconds)
 * Returns true if token expires within thresholdSeconds.
 * Use in long load test runs to decide when to regenerate.
 *
 * Example (token expires in 15 min, refresh when < 5 min left):
 *   if (!currentToken || jwt.isExpiring(currentToken, 300)) {
 *       currentToken = jwt.generate({ ... });
 *   }
 *
 * @param  {string} token            - JWT token string
 * @param  {number} thresholdSeconds - Seconds before expiry to warn
 * @returns {boolean} true if expiring soon or no exp claim
 * ============================================================ */
function isExpiring(token, thresholdSeconds) {
    try {
        const payload = decode(token);
        if (typeof payload.exp !== 'number') return true; /* No exp claim - treat as expiring */
        const nowSeconds = Math.floor(Date.now() / 1000);
        return (payload.exp - nowSeconds) < thresholdSeconds;
    } catch (e) {
        return true; /* Can't decode - treat as expiring */
    }
}

/* ============================================================
 * getVersion() - Returns library version string
 * ============================================================ */
function getVersion() {
    return VERSION;
}

/* ============================================================
 * isAlgorithmSupported(algorithm) - Check algorithm support
 * @returns {boolean}
 * ============================================================ */
function isAlgorithmSupported(algorithm) {
    if (!algorithm) return false;
    const supported = [
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'PS256', 'PS384', 'PS512',
        'ES256', 'ES384', 'ES512'
    ];
    return supported.includes(algorithm.toUpperCase());
}

/* ============================================================
 * Module Exports
 * ============================================================ */
module.exports = {
    generate,
    decode,
    isExpiring,
    getVersion,
    isAlgorithmSupported
};
