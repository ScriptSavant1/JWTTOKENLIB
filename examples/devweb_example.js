/**
 * devweb_example.js - Complete DevWeb Protocol Example Script
 * ============================================================
 *
 * Production-ready DevWeb script demonstrating JWT token generation
 * using jwt-lib.js.
 *
 * Script root folder structure:
 *   main.js              ← this file (rename to main.js)
 *   jwt-lib.js           ← JWT library (copy from project root)
 *   private_key.pem      ← RSA private key for PS256
 *
 * rts.yaml example (alternative to key file):
 *   parameters:
 *     PrivateKeyPEM: |
 *       -----BEGIN PRIVATE KEY-----
 *       MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
 *       -----END PRIVATE KEY-----
 *
 * ============================================================
 */

'use strict';

/* Load JWT library - must be in same folder as main.js */
const jwt = require('./jwt-lib');

/* ============================================================
 * Initialize - runs once before all virtual users start
 * Load the private key into memory once (shared across iterations).
 * This is the most efficient approach for file-based keys.
 * ============================================================ */
load.initialize('Setup', async function() {
    /* Log library version to confirm it loaded */
    load.log(`JWT Library version: ${jwt.getVersion()}`);

    /*
     * Option A: Load key from file (in script root folder)
     * The file is loaded once at init and reused for all tokens.
     */
    const fs = require('fs');
    global.privateKey = fs.readFileSync('./private_key.pem', 'utf8');
    load.log('Private key loaded from file.');

    /*
     * Option B: Get key from rts.yaml parameter (uncomment to use)
     * The parameter value is the full PEM content as a string.
     *
     * global.privateKey = load.params.get('PrivateKeyPEM');
     * load.log('Private key loaded from rts.yaml parameter.');
     */

    /* Verify PS256 is supported */
    if (!jwt.isAlgorithmSupported('PS256')) {
        throw new Error('PS256 not supported - check jwt-lib.js version');
    }
    load.log('JWT initialization complete. PS256 ready.');
});

/* ============================================================
 * Action - runs for each transaction iteration per VUser
 * ============================================================ */
load.action('API_Transactions', async function() {
    const userId  = load.config.user.userId;  /* Unique per VUser */
    const now     = Math.floor(Date.now() / 1000);

    /*
     * Generate JWT token for this VUser.
     * Each token is unique: different sub, iat, jti, exp.
     *
     * For LONG load test runs (> 15 minutes):
     * Check if current token is expiring and regenerate if needed.
     * Using global per-VUser token storage:
     */
    if (!global.currentToken || jwt.isExpiring(global.currentToken, 300)) {
        global.currentToken = jwt.generate({
            algorithm: 'PS256',

            payload: {
                /* Standard JWT claims (RFC 7519) */
                iss: 'loadtest-system',
                sub: `user-${userId}`,
                aud: 'api.production.com',
                exp: now + 900,     /* Token valid for 15 minutes */
                iat: now,
                jti: `req-${userId}-${now}`,

                /* Custom application claims */
                userId:    `USER${String(userId).padStart(5, '0')}`,
                email:     `user${userId}@loadtest.com`,
                role:      'customer',
                tenantId:  'tenant-001',
                sessionId: `sess-${userId}-${now}`
            },

            /*
             * Option A: Key from memory (loaded in initialize)
             * Most efficient - key loaded once per script
             */
            key: global.privateKey

            /*
             * Option B: Key from file path (re-read each time, less efficient)
             * keyPath: './private_key.pem'
             */

            /*
             * Option C: Add custom header fields (e.g. Key ID)
             * header: { kid: 'key-id-2024' }
             */
        });

        load.log(`Token generated for user ${userId}`);
    }

    /* ---- Transaction 1: GET request with JWT ---- */
    const getResponse = await new load.WebRequest({
        id:     'API_Get_Data',
        url:    'https://api.production.com/v1/data',
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${global.currentToken}`,
            'Content-Type':  'application/json',
            'X-User-ID':     String(userId)
        }
    }).send();

    load.log(`GET /data - Status: ${getResponse.status}`);

    if (getResponse.status !== 200) {
        load.log(`WARNING: Unexpected status ${getResponse.status} for GET /data`);
    }

    /* ---- Transaction 2: POST request with JWT ---- */
    const postResponse = await new load.WebRequest({
        id:     'API_Post_Data',
        url:    'https://api.production.com/v1/orders',
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${global.currentToken}`,
            'Content-Type':  'application/json'
        },
        body: JSON.stringify({
            userId:  `USER${String(userId).padStart(5, '0')}`,
            action:  'create_order',
            amount:  100.00,
            currency: 'USD'
        })
    }).send();

    load.log(`POST /orders - Status: ${postResponse.status}`);

    /* ---- Transaction 3: HS256 example (if using shared secret) ---- */
    /*
    const hmacToken = jwt.generate({
        algorithm: 'HS256',
        payload: {
            sub: `user-${userId}`,
            exp: now + 3600,
            iat: now,
            role: 'service'
        },
        secret: load.params.get('HMACSecret')  // from rts.yaml
    });

    await new load.WebRequest({
        id:  'Internal_API_Call',
        url: 'https://internal-api.company.com/v1/data',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${hmacToken}` }
    }).send();
    */
});

/* ============================================================
 * Finalize - runs once after all virtual users complete
 * ============================================================ */
load.finalize('Teardown', async function() {
    load.log('DevWeb JWT test complete.');
});
