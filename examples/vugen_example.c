/*
 * vugen_example.c - Complete VuGen WEB HTTP/HTML Example Script
 * ==============================================================
 *
 * This is a complete, production-ready VuGen script demonstrating
 * JWT token generation using JWTTokenLib.
 *
 * Prerequisites:
 *   Windows LG: Copy JWTTokenLib.dll to C:\Program Files\LoadRunner\bin\
 *   Linux LG:   Copy libJWTTokenLib.so to /opt/HP/LoadRunner/lib/
 *
 * Script structure:
 *   extras/private_key.pem    <- RSA private key for PS256
 *
 * rts.yaml parameters (alternative to file):
 *   PrivateKeyPEM: |
 *     -----BEGIN PRIVATE KEY-----
 *     ...full PEM content...
 *     -----END PRIVATE KEY-----
 *
 * ==============================================================
 */

/* ============================================================
 * VUSER INIT - Called once per VUser at startup
 * Load the DLL and verify it works before the test begins.
 * ============================================================ */
vuser_init()
{
    /*
     * Load the DLL.
     * Windows: DLL must be in LoadRunner bin/ or same folder as script.
     * Linux:   Use libJWTTokenLib.so
     */
#ifdef WIN32
    lr_load_dll("JWTTokenLib.dll");
#else
    lr_load_dll("libJWTTokenLib.so");
#endif

    /* Verify library loaded correctly */
    lr_log_message("JWT Library version: %s", JWT_Get_Version());

    /* Verify PS256 is supported (primary algorithm) */
    if (!JWT_Is_Algorithm_Supported("PS256")) {
        lr_error_message("PS256 algorithm not supported - check DLL version");
        return -1;
    }

    lr_log_message("JWT Library initialized. PS256 ready.");
    return 0;
}

/* ============================================================
 * ACTION - Called for each transaction iteration
 *
 * Demonstrates:
 * 1. Building a realistic JWT payload with standard + custom claims
 * 2. Generating the token (PS256 via PEM file)
 * 3. Using the token in HTTP requests
 * 4. Refreshing the token when near expiry (for long test runs)
 * ============================================================ */
Action()
{
    /* Persistent token storage across iterations */
    static char jwt_token[4096] = {0};

    char   payload[2048];
    int    vuser_id;
    long   current_time;
    long   exp_time;
    int    rc;

    /* Get current VUser ID and timestamp */
    vuser_id     = lr_get_vuser_id();
    current_time = (long)time(NULL);
    exp_time     = current_time + 900;  /* Token valid for 15 minutes */

    /*
     * Generate token if:
     *   - First iteration (token is empty)
     *   - Token is expiring in less than 5 minutes (300 seconds)
     *
     * This handles long load test runs where tokens expire mid-test.
     */
    if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300) == 1)
    {
        /* Build the JWT payload with standard RFC 7519 claims */
        sprintf(payload,
            "{"
            "\"iss\":\"loadtest-system\","
            "\"sub\":\"user-%d\","
            "\"aud\":\"api.production.com\","
            "\"exp\":%ld,"
            "\"iat\":%ld,"
            "\"jti\":\"req-%d-%ld\","
            "\"userId\":\"USER%05d\","
            "\"email\":\"user%d@loadtest.com\","
            "\"role\":\"customer\","
            "\"tenantId\":\"tenant-001\""
            "}",
            vuser_id,           /* sub: unique per VUser */
            exp_time,           /* exp: token expiry */
            current_time,       /* iat: issued at */
            vuser_id,           /* jti: unique request ID */
            current_time,
            vuser_id,           /* userId custom claim */
            vuser_id            /* email custom claim */
        );

        /*
         * Option A: Key from file (in extras/ folder)
         * The extras/ folder is in the same directory as the script.
         */
        rc = JWT_Generate(
            "PS256",                        /* Algorithm (primary) */
            payload,                        /* Payload JSON */
            "extras/private_key.pem",       /* PEM key file path */
            jwt_token,                      /* Output buffer */
            sizeof(jwt_token)               /* Buffer size */
        );

        /*
         * Option B: Key from rts.yaml parameter (uncomment to use)
         * Set parameter PrivateKeyPEM in rts.yaml with full PEM content.
         *
         * rc = JWT_Generate(
         *     "PS256",
         *     payload,
         *     lr_eval_string("{PrivateKeyPEM}"),  <- rts.yaml parameter
         *     jwt_token,
         *     sizeof(jwt_token)
         * );
         */

        if (rc != JWT_SUCCESS) {
            lr_error_message("JWT_Generate failed (error %d): %s",
                rc, JWT_Get_Error_Message(rc));
            return -1;
        }

        /* Save token as LR parameter for use with lr_eval_string */
        lr_save_string(jwt_token, "JWT_Token");
        lr_log_message("Token generated for VUser %d (expires in 15 min)", vuser_id);
    }

    /* ----------------------------------------------------------------
     * Transaction: Protected API Call
     * Use the JWT token in the Authorization header.
     * ---------------------------------------------------------------- */
    lr_start_transaction("API_Get_Data");

    web_add_header("Authorization", lr_eval_string("Bearer {JWT_Token}"));
    web_add_header("Content-Type",  "application/json");
    web_add_header("X-Request-ID",  lr_eval_string("{jti}"));

    web_url("Protected_API",
        "URL=https://api.production.com/v1/data",
        "Method=GET",
        EXTRARES,
        LAST);

    lr_end_transaction("API_Get_Data", LR_AUTO);

    /* ----------------------------------------------------------------
     * Transaction: Protected POST with body
     * ---------------------------------------------------------------- */
    lr_start_transaction("API_Post_Data");

    web_add_header("Authorization", lr_eval_string("Bearer {JWT_Token}"));
    web_add_header("Content-Type",  "application/json");

    web_submit_data("Submit_Data",
        "Action=https://api.production.com/v1/data",
        "Method=POST",
        "EncType=application/json",
        ITEMDATA,
        "Name=Body", "Value={\"message\":\"loadtest\",\"userId\":\"USER%05d\"}", ENDITEM,
        LAST);

    lr_end_transaction("API_Post_Data", LR_AUTO);

    return 0;
}

/* ============================================================
 * VUSER END - Called once per VUser at shutdown
 * ============================================================ */
vuser_end()
{
    return 0;
}

/* ============================================================
 * GLOBALS (paste into globals.h in VuGen)
 * ============================================================ */

/*
 * Paste these declarations into your globals.h file:
 *
 * #include <time.h>
 *
 * // JWT Library API declarations
 * int         JWT_Generate(const char* alg, const char* payload,
 *                          const char* key, char* out, int size);
 * int         JWT_Is_Token_Expiring(const char* token, int threshold_sec);
 * const char* JWT_Get_Error_Message(int error_code);
 * const char* JWT_Get_Version(void);
 * int         JWT_Is_Algorithm_Supported(const char* algorithm);
 */
