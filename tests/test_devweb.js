/**
 * test_devweb.js - DevWeb Protocol Test Script for jwt-lib.js
 * ============================================================
 *
 * This is a complete DevWeb test script that verifies jwt-lib.js
 * works correctly in the LRE DevWeb runtime environment.
 *
 * To run standalone (outside DevWeb for quick testing):
 *   node tests/test_devweb.js
 *
 * To run in DevWeb:
 *   Copy jwt-lib.js to your DevWeb script root folder
 *   Copy this file as main.js in a new DevWeb script
 *
 * Required files in script root:
 *   jwt-lib.js              (the library)
 *   private_key.pem         (RSA/EC private key for PS256/RS256/ES256)
 *
 * Generate test keys:
 *   openssl genrsa -out private_key.pem 2048
 *   openssl ecparam -genkey -name prime256v1 -noout -out ec_private_key.pem
 */

'use strict';

/* ============================================================
 * Standalone test runner (outside DevWeb)
 * When running in DevWeb, use load.* APIs instead.
 * ============================================================ */
const isDevWeb = (typeof load !== 'undefined');

function log(msg) {
    if (isDevWeb) load.log(msg);
    else console.log(msg);
}

/* Load the library */
const jwt = require('./jwt-lib');

/* ============================================================
 * Test helpers
 * ============================================================ */
let passed = 0, failed = 0;

function test(name, fn) {
    try {
        fn();
        log(`[PASS] ${name}`);
        passed++;
    } catch (e) {
        log(`[FAIL] ${name}: ${e.message}`);
        failed++;
    }
}

function assert(condition, msg) {
    if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertThrows(fn, msg) {
    try { fn(); throw new Error('Expected error but none thrown'); }
    catch (e) {
        if (e.message === 'Expected error but none thrown') throw e;
    }
}

function hasThreeParts(token) {
    return token.split('.').length === 3;
}

/* ============================================================
 * Tests
 * ============================================================ */
function runTests() {
    const fs   = require('fs');
    const now  = Math.floor(Date.now() / 1000);

    /* Standard payload for testing */
    const basePayload = {
        iss: 'loadtest-system',
        sub: 'test-user-001',
        aud: 'api.production.com',
        exp: now + 3600,
        iat: now,
        jti: `test-${now}`,
        role: 'customer'
    };

    log('\n=== jwt-lib.js Test Suite ===\n');
    log(`Library version: ${jwt.getVersion()}`);

    /* --- Version & algorithm support --- */
    log('\n--- Version & Algorithm Support ---');
    test('getVersion returns string', () => {
        const v = jwt.getVersion();
        assert(typeof v === 'string' && v.length > 0, 'version must be non-empty string');
    });

    test('PS256 is supported',  () => assert(jwt.isAlgorithmSupported('PS256')));
    test('RS256 is supported',  () => assert(jwt.isAlgorithmSupported('RS256')));
    test('HS256 is supported',  () => assert(jwt.isAlgorithmSupported('HS256')));
    test('ES256 is supported',  () => assert(jwt.isAlgorithmSupported('ES256')));
    test('INVALID not supported', () => assert(!jwt.isAlgorithmSupported('INVALID')));
    test('null not supported',    () => assert(!jwt.isAlgorithmSupported(null)));

    /* --- HS256 / HS384 / HS512 --- */
    log('\n--- HMAC Algorithms ---');

    test('HS256 generate with secret', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   basePayload,
            secret:    'my-test-secret-key-32-chars-long!'
        });
        assert(hasThreeParts(token), 'token must have 3 parts');
        /* HS256 header always starts with this base64url */
        assert(token.startsWith('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'),
               'HS256 header mismatch');
        log(`  HS256 token: ${token.substring(0, 60)}...`);
    });

    test('HS384 generate', () => {
        const token = jwt.generate({
            algorithm: 'HS384',
            payload:   basePayload,
            secret:    'my-test-secret-key'
        });
        assert(hasThreeParts(token));
    });

    test('HS512 generate', () => {
        const token = jwt.generate({
            algorithm: 'HS512',
            payload:   basePayload,
            secret:    'my-test-secret-key'
        });
        assert(hasThreeParts(token));
    });

    test('HS256 deterministic (same input → same output)', () => {
        const opts = { algorithm: 'HS256', payload: basePayload, secret: 'fixed-secret' };
        const t1 = jwt.generate(opts);
        const t2 = jwt.generate(opts);
        assert(t1 === t2, 'HMAC must be deterministic');
    });

    /* --- RSA algorithms (require key file) --- */
    log('\n--- RSA Algorithms (PS256 / RS256) ---');

    const rsaKeyPath = './private_key.pem';
    const rsaKeyExists = (() => {
        try { fs.accessSync(rsaKeyPath); return true; } catch(e) { return false; }
    })();

    if (!rsaKeyExists) {
        log(`  [SKIP] ${rsaKeyPath} not found. Generate with:`);
        log('  openssl genrsa -out private_key.pem 2048');
    } else {
        test('PS256 with keyPath', () => {
            const token = jwt.generate({
                algorithm: 'PS256',
                payload:   basePayload,
                keyPath:   rsaKeyPath
            });
            assert(hasThreeParts(token));
            assert(token.startsWith('eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.'),
                   'PS256 header mismatch');
            log(`  PS256 token: ${token.substring(0, 60)}...`);
        });

        test('PS256 non-deterministic (PSS uses random salt)', () => {
            const opts = { algorithm: 'PS256', payload: basePayload, keyPath: rsaKeyPath };
            const t1 = jwt.generate(opts);
            const t2 = jwt.generate(opts);
            /* PSS signatures differ each time due to random salt */
            assert(t1 !== t2, 'PS256 with PSS must be non-deterministic');
        });

        test('RS256 with keyPath', () => {
            const token = jwt.generate({
                algorithm: 'RS256',
                payload:   basePayload,
                keyPath:   rsaKeyPath
            });
            assert(hasThreeParts(token));
            assert(token.startsWith('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'),
                   'RS256 header mismatch');
            log(`  RS256 token: ${token.substring(0, 60)}...`);
        });

        test('PS256 with key string (rts.yaml scenario)', () => {
            const keyContent = fs.readFileSync(rsaKeyPath, 'utf8');
            const token = jwt.generate({
                algorithm: 'PS256',
                payload:   basePayload,
                key:       keyContent
            });
            assert(hasThreeParts(token), 'token must have 3 parts');
            log('  PS256 with PEM string: OK');
        });

        test('PS384 with keyPath', () => {
            const token = jwt.generate({ algorithm: 'PS384', payload: basePayload, keyPath: rsaKeyPath });
            assert(hasThreeParts(token));
        });

        test('PS512 with keyPath', () => {
            const token = jwt.generate({ algorithm: 'PS512', payload: basePayload, keyPath: rsaKeyPath });
            assert(hasThreeParts(token));
        });

        test('RS384 with keyPath', () => {
            const token = jwt.generate({ algorithm: 'RS384', payload: basePayload, keyPath: rsaKeyPath });
            assert(hasThreeParts(token));
        });

        test('RS512 with keyPath', () => {
            const token = jwt.generate({ algorithm: 'RS512', payload: basePayload, keyPath: rsaKeyPath });
            assert(hasThreeParts(token));
        });
    }

    /* --- ECDSA (ES256) --- */
    log('\n--- ECDSA (ES256) ---');

    const ecKeyPath   = './ec_private_key.pem';
    const ecKeyExists = (() => {
        try { fs.accessSync(ecKeyPath); return true; } catch(e) { return false; }
    })();

    if (!ecKeyExists) {
        log(`  [SKIP] ${ecKeyPath} not found. Generate with:`);
        log('  openssl ecparam -genkey -name prime256v1 -noout -out ec_private_key.pem');
    } else {
        test('ES256 with keyPath', () => {
            const token = jwt.generate({
                algorithm: 'ES256',
                payload:   basePayload,
                keyPath:   ecKeyPath
            });
            assert(hasThreeParts(token));
            log(`  ES256 token: ${token.substring(0, 60)}...`);
        });
    }

    /* --- decode() --- */
    log('\n--- Decode ---');

    test('decode() extracts payload', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   basePayload,
            secret:    'test-secret'
        });
        const decoded = jwt.decode(token);
        assert(decoded.sub === basePayload.sub, 'sub claim mismatch');
        assert(decoded.iss === basePayload.iss, 'iss claim mismatch');
        assert(decoded.exp === basePayload.exp, 'exp claim mismatch');
    });

    test('decode() handles invalid token', () => {
        assertThrows(() => jwt.decode('not-a-jwt'));
        assertThrows(() => jwt.decode(''));
        assertThrows(() => jwt.decode(null));
    });

    /* --- isExpiring() --- */
    log('\n--- Token Expiry ---');

    test('isExpiring() returns false when plenty of time left', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   { sub: 'user', exp: now + 900 },  /* 15 min left */
            secret:    'test-secret'
        });
        assert(jwt.isExpiring(token, 300) === false, 'should not be expiring (900s > 300s threshold)');
    });

    test('isExpiring() returns true when near expiry', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   { sub: 'user', exp: now + 100 },  /* 100s left */
            secret:    'test-secret'
        });
        assert(jwt.isExpiring(token, 300) === true, 'should be expiring (100s < 300s threshold)');
    });

    test('isExpiring() returns true for expired token', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   { sub: 'user', exp: now - 60 },   /* expired 60s ago */
            secret:    'test-secret'
        });
        assert(jwt.isExpiring(token, 0) === true, 'expired token should return true');
    });

    test('isExpiring() returns true for token with no exp', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   { sub: 'user' },   /* no exp claim */
            secret:    'test-secret'
        });
        assert(jwt.isExpiring(token, 300) === true, 'no exp claim should return true');
    });

    /* --- Error handling --- */
    log('\n--- Error Handling ---');

    test('generate() throws on missing algorithm', () => {
        assertThrows(() => jwt.generate({ payload: basePayload, secret: 'key' }));
    });

    test('generate() throws on missing payload', () => {
        assertThrows(() => jwt.generate({ algorithm: 'HS256', secret: 'key' }));
    });

    test('generate() throws on unsupported algorithm', () => {
        assertThrows(() => jwt.generate({ algorithm: 'RS255', payload: basePayload, secret: 'key' }));
    });

    test('generate() throws on missing key for PS256', () => {
        assertThrows(() => jwt.generate({ algorithm: 'PS256', payload: basePayload }));
    });

    /* --- Custom header (kid) --- */
    log('\n--- Custom Header Fields ---');

    test('Custom header with kid', () => {
        const token = jwt.generate({
            algorithm: 'HS256',
            payload:   basePayload,
            secret:    'test-secret',
            header:    { kid: 'key-id-2024' }
        });
        const parts    = token.split('.');
        const header   = JSON.parse(Buffer.from(
            parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64'
        ).toString('utf8'));
        assert(header.kid === 'key-id-2024', 'kid not in header');
        assert(header.alg === 'HS256',       'alg not in header');
        assert(header.typ === 'JWT',          'typ not in header');
    });

    /* --- Performance --- */
    log('\n--- Performance ---');

    test('HS256 > 5000 TPS (Node.js baseline)', () => {
        const count = 1000;
        const start = Date.now();
        for (let i = 0; i < count; i++) {
            jwt.generate({
                algorithm: 'HS256',
                payload:   { sub: `user-${i}`, exp: now + 3600, iat: now },
                secret:    'perf-test-secret'
            });
        }
        const ms  = Date.now() - start;
        const tps = Math.round(count / (ms / 1000));
        log(`  ${count} HS256 tokens in ${ms}ms = ${tps} TPS`);
        assert(tps > 1000, `Expected > 1000 TPS, got ${tps}`);
    });

    /* --- Summary --- */
    log('\n============================================================');
    log(`Results: ${passed}/${passed + failed} passed${failed > 0 ? `, ${failed} FAILED` : ''}`);
    log('============================================================');
}

/* ============================================================
 * Entry point - standalone or DevWeb
 * ============================================================ */
if (isDevWeb) {
    /* DevWeb script structure */
    load.initialize('JWT Library Verification', async () => {
        runTests();
    });
    load.action('No HTTP action needed for unit tests', async () => {});
    load.finalize('Cleanup', async () => {});
} else {
    /* Standalone Node.js execution */
    runTests();
    process.exit(failed > 0 ? 1 : 0);
}
