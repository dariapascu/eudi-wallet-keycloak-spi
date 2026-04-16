package com.license.eudi;

import com.license.eudi.openid4vp.PresentationDefinitionBuilder;
import com.license.eudi.openid4vp.RequestObjectManager;
import com.license.eudi.session.SessionStateManager;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class EudiVerifierAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(EudiVerifierAuthenticator.class);

    private static final String NGROK_BASE_URL = resolveBaseUrl();

    private static String resolveBaseUrl() {
        String envUrl = System.getenv("EUDI_VERIFIER_BASE_URL");
        if (envUrl != null && !envUrl.isBlank()) {
            return envUrl.endsWith("/") ? envUrl.substring(0, envUrl.length() - 1) : envUrl;
        }
        return "https://prestidigitatory-bee-unquivered.ngrok-free.dev";
    }
    
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.info("========== AUTHENTICATE METHOD CALLED ==========");
        
        // Verifica daca e POST request - polling-ul a detectat success
        String method = context.getHttpRequest().getHttpMethod();
        String authSessionId = context.getAuthenticationSession().getParentSession().getId();
        LOG.infof("HTTP Method: %s, AuthSessionId: %s", method, authSessionId);
        
        // Verifica intotdeauna daca avem un state autentificat (indiferent de GET/POST)
        String state = SessionStateManager.getInstance().getStateByAuthSession(authSessionId);
        LOG.infof("Looking up state for authSessionId=%s, found state=%s", authSessionId, state);
        
        if (state != null) {
            boolean isAuth = SessionStateManager.getInstance().isAuthenticated(state);
            LOG.infof("State %s authenticated status: %s", state, isAuth);
            
            if (isAuth) {
                LOG.info("Found authenticated state - proceeding with user provisioning");
                handleAuthenticatedState(context, state);
                return;
            }
        }    
        // ADAUGAT PT BENCHMARK: verifica parametrul eudi_state_confirmed din URL
        // Scriptul il adauga explicit in Step 5 pentru a evita dependenta de auth note / session code
        // String eudiStateParam = context.getHttpRequest().getUri().getQueryParameters().getFirst("eudi_state_confirmed");
        // LOG.infof("eudi_state_confirmed URL param: %s", eudiStateParam);
        // if (eudiStateParam != null) {
        //     SessionStateManager.SessionData paramData = SessionStateManager.getInstance().getSessionData(eudiStateParam);
        //     if (paramData != null && paramData.isAuthenticated()) {
        //         LOG.infof("Found authenticated state from URL param: %s", eudiStateParam);
        //         handleAuthenticatedState(context, eudiStateParam);
        //         return;
        //     }
        // }

        // // Read state directly from auth session notes (stable across reloads)
        // String state = context.getAuthenticationSession().getAuthNote("eudi_state");
        // LOG.infof("Looking up eudi_state from auth note: authSessionId=%s, found state=%s", authSessionId, state);

        if (state != null) {
            boolean isAuth = SessionStateManager.getInstance().isAuthenticated(state);
            LOG.infof("State %s authenticated status: %s", state, isAuth);

            if (isAuth) {
                LOG.info("Found authenticated state - proceeding with user provisioning");
                handleAuthenticatedState(context, state);
                return;
            }
        }

        
        // Nu avem state autentificat - generam QR code
        LOG.info("No authenticated state found - generating QR code");
        
        try {
            AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
            String clientId = cfgString(cfg, EudiVerifierAuthenticatorFactory.CFG_CLIENT_ID,
                    context.getRealm().getName() + "-verifier");
            String pidVct = cfgString(cfg, EudiVerifierAuthenticatorFactory.CFG_PID_VCT,
                    EudiVerifierAuthenticatorFactory.DEFAULT_PID_VCT);
            String diplomaVct = cfgString(cfg, EudiVerifierAuthenticatorFactory.CFG_DIPLOMA_VCT,
                    EudiVerifierAuthenticatorFactory.DEFAULT_DIPLOMA_VCT);
            long stateTimeoutMs = TimeUnit.MINUTES.toMillis(cfgInt(cfg,
                    EudiVerifierAuthenticatorFactory.CFG_STATE_TIMEOUT_MIN,
                    EudiVerifierAuthenticatorFactory.DEFAULT_STATE_TIMEOUT_MIN));
            long kbJwtMaxAgeMs = TimeUnit.SECONDS.toMillis(cfgInt(cfg,
                    EudiVerifierAuthenticatorFactory.CFG_KBJWT_MAX_AGE_SEC,
                    EudiVerifierAuthenticatorFactory.DEFAULT_KBJWT_MAX_AGE_SEC));

            String nonce = UUID.randomUUID().toString();
            String callbackUrl = buildCallbackUrl(context);

            String credentialType = detectCredentialType(context);
            LOG.infof("Detected credential type: %s", credentialType);

            String expectedVct;
            String presentationDefinition;
            if ("diploma".equals(credentialType)) {
                expectedVct = diplomaVct;
                presentationDefinition = PresentationDefinitionBuilder.buildDiplomaPresentationDefinition();
                LOG.info("Using diploma presentation definition");
            } else {
                expectedVct = pidVct;
                presentationDefinition = PresentationDefinitionBuilder.buildPidPresentationDefinition();
                LOG.info("Using PID presentation definition");
            }

            context.getAuthenticationSession().setAuthNote("credential_type", credentialType);

            String newState = SessionStateManager.getInstance()
                .createState(authSessionId, nonce, callbackUrl, clientId, expectedVct, stateTimeoutMs, kbJwtMaxAgeMs);
            LOG.infof("Created new state: %s for authSessionId: %s", newState, authSessionId);

            //ADAUGAT PT TIMP
            context.getAuthenticationSession().setAuthNote("eudi_state", newState);



            String requestId = RequestObjectManager.getInstance().createRequestObject(
                clientId,
                callbackUrl,
                nonce,
                newState,
                presentationDefinition
            );
            
            String requestUri = NGROK_BASE_URL + "/realms/" + context.getRealm().getName() + 
                               "/eudi-verifier/request/" + requestId;
            
            String authRequestUrl = String.format("openid4vp://?client_id=%s&client_id_scheme=pre-registered&request_uri=%s",
                java.net.URLEncoder.encode(clientId, java.nio.charset.StandardCharsets.UTF_8),
                java.net.URLEncoder.encode(requestUri, java.nio.charset.StandardCharsets.UTF_8));
            
            LOG.infof("Generated QR code URL: %s", authRequestUrl);
            LOG.infof("Request URI: %s", requestUri);
            LOG.infof("Callback URL: %s", callbackUrl);
            LOG.infof("State: %s, Nonce: %s", newState, nonce);
            
            String html = generateQrPageHtml(authRequestUrl, newState, callbackUrl);
            
            Response challenge = Response.ok(html)
                .type("text/html; charset=UTF-8")
                .build();
            
            context.challenge(challenge);
            
        } catch (Exception e) {
            LOG.error("Error generating authorization request", e);
            context.failure(org.keycloak.authentication.AuthenticationFlowError.INTERNAL_ERROR);
        }
    }
    
    /**
     * Construieste URL-ul de callback unde EUDI wallet va trimite VP Token-ul
     * Foloseste ngrok URL
     */
    private String buildCallbackUrl(AuthenticationFlowContext context) {
        // Foloseste ngrok URL in loc de localhost
        return NGROK_BASE_URL + "/realms/" + context.getRealm().getName() + "/eudi-verifier/callback";
    }
    
   /**
 * Detecteaza tipul de credential cerut (PID sau diploma)
 * Verifica parametrul acr_values din request OAuth2
 * Format asteptat: acr_values=credential_type:diploma sau credential_type:pid
 */
private String detectCredentialType(AuthenticationFlowContext context) {
    String storedType = context.getAuthenticationSession().getAuthNote("credential_type");
    if (storedType != null && !storedType.isEmpty()) {
        LOG.infof("Found stored credential type in auth note: %s", storedType);
        return storedType;
    }
    
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String acrValues = authSession.getClientNote("acr");
    
    if (acrValues == null) {
        acrValues = context.getUriInfo().getQueryParameters().getFirst("acr_values");
    }
    
    LOG.infof("ACR values: %s", acrValues);
    
    if (acrValues != null && acrValues.contains("credential_type:")) {
        String[] parts = acrValues.split("credential_type:");
        if (parts.length > 1) {
            String type = parts[1].split(" ")[0].trim();
            LOG.infof("Extracted credential type from acr_values: %s", type);
            return type;
        }
    }
    
    LOG.info("No credential type specified, defaulting to PID");
    return "pid";
}

    @Override
    public void action(AuthenticationFlowContext context) {
        LOG.info("========== ACTION METHOD CALLED ==========");
        
        String authSessionId = context.getAuthenticationSession().getParentSession().getId();
        LOG.infof("Auth session ID: %s", authSessionId);
        
        String state = SessionStateManager.getInstance().getStateByAuthSession(authSessionId);
        LOG.infof("Retrieved state for session: %s", state);
        
        if (state != null && SessionStateManager.getInstance().isAuthenticated(state)) {
            handleAuthenticatedState(context, state);
        } else {
            LOG.infof("State not authenticated yet or not found. State: %s, Authenticated: %s", 
                     state, state != null ? SessionStateManager.getInstance().isAuthenticated(state) : "null");
            authenticate(context);
        }
    }
    
    /**
     * Gestioneaza un state autentificat - provisioneaza user si finalizeaza autentificarea
     */
    private void handleAuthenticatedState(AuthenticationFlowContext context, String state) {
        LOG.infof("handleAuthenticatedState called with state: %s", state);
        
        Map<String, Object> claims = SessionStateManager.getInstance().getClaims(state);
        LOG.infof("Retrieved %d claims from SessionStateManager", claims != null ? claims.size() : 0);
        
        if (claims == null || claims.isEmpty()) {
            LOG.warn("No claims found for authenticated state: " + state);
            context.failure(org.keycloak.authentication.AuthenticationFlowError.INVALID_USER);
            return;
        }
        
        LOG.infof("Claims received: %s", claims.keySet());
        
        String vct = claims.get("vct") != null ? String.valueOf(claims.get("vct")) : "";
        String credentialType = vct.equals(EudiVerifierAuthenticatorFactory.DEFAULT_DIPLOMA_VCT) ? "diploma" : "pid";


        UserModel user = provisionUser(context, claims, credentialType);
        
        if (user == null) {
            LOG.error("Failed to provision user from claims");
            context.failure(org.keycloak.authentication.AuthenticationFlowError.INVALID_USER);
            return;
        }
        
        context.setUser(user);
        context.success();
        
        LOG.infof("========== AUTHENTICATION SUCCESS for user '%s' via EUDI Wallet ==========", user.getUsername());
    }
    
    /**
     * Creeaza sau actualizeaza un user Keycloak bazat pe claims-urile din VP Token.
     *
     * Atributele sunt stocate prefixate cu tipul credentialului (pid_ / diploma_)
     * pentru a evita suprascrierea datelor intre tipuri diferite de credentiale.
     */
    private UserModel provisionUser(AuthenticationFlowContext context, Map<String, Object> claims,
                                    String credentialType) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        String uniqueId = extractUniqueId(claims);
        if (uniqueId == null || uniqueId.isEmpty()) {
            LOG.error("No unique identifier found in claims");
            return null;
        }

        LOG.infof("Provisioning user with unique ID: %s, credentialType: %s",
                  maskPii(uniqueId), credentialType);

        UserModel user = session.users().getUserByUsername(realm, uniqueId);

        if (user == null) {
            LOG.infof("Creating new user for credentialType=%s", credentialType);
            user = session.users().addUser(realm, uniqueId);
            user.setEnabled(true);
        } else {
            LOG.infof("Updating existing user for credentialType=%s", credentialType);
        }

        updateUserAttributes(user, claims, credentialType);

        return user;
    }
    
    /**
     * Extrage identificatorul unic din claims.
     *
     * Prioritate:
     * 1. unique_id (PID — emis de stat, garantat unic la nivel national)
     * 2. sub (standard JWT subject — unic per issuer)
     * 3. student_id / studentId (diploma — unic per universitate)
     * 4. email (daca exista)
     */
    private String extractUniqueId(Map<String, Object> claims) {
        LOG.infof("Extracting unique ID from claims: %s", claims.keySet());

        // 1. unique_id din PID — identificator national unic
        if (claims.containsKey("unique_id")) {
            String uid = String.valueOf(claims.get("unique_id"));
            LOG.infof("Using unique_id as identifier: %s", maskPii(uid));
            return uid;
        }

        // 2. sub — unic per issuer (standard JWT)
        if (claims.containsKey("sub")) {
            String sub = String.valueOf(claims.get("sub"));
            LOG.infof("Using sub as identifier: %s", maskPii(sub));
            return sub;
        }

        // 3. student_id / studentId pentru credentiale de diploma
        if (claims.containsKey("student_id")) {
            String sid = String.valueOf(claims.get("student_id"));
            LOG.infof("Using student_id as identifier: %s", maskPii(sid));
            return sid;
        }
        if (claims.containsKey("studentId")) {
            String sid = String.valueOf(claims.get("studentId"));
            LOG.infof("Using studentId as identifier: %s", maskPii(sid));
            return sid;
        }

        // 4. email
        if (claims.containsKey("email")) {
            String email = String.valueOf(claims.get("email"));
            LOG.infof("Using email as identifier: %s", maskEmail(email));
            return email;
        }

        LOG.error("No stable unique identifier found in claims — cannot provision user safely");
        return null;
    }
    
    /**
     * Actualizeaza atributele user-ului din claims-urile VP Token.
     *
     * Toate atributele specifice unui credential sunt stocate cu prefix (pid_ / diploma_)
     * pentru a evita coliziunile cand acelasi user se autentifica cu tipuri diferite.
     *
     * firstName si lastName din profilul Keycloak sunt setate NUMAI din PID —
     * documentul de identitate de stat este sursa autoritativa pentru identitate.
     */
    private void updateUserAttributes(UserModel user, Map<String, Object> claims, String credentialType) {
        boolean isPid = "pid".equals(credentialType);
        String prefix = isPid ? "pid_" : "diploma_";

        setAttrIfPresent(user, prefix + "given_name",  claims, "given_name", "firstName");
        setAttrIfPresent(user, prefix + "family_name", claims, "family_name", "lastName");
        setAttrIfPresent(user, prefix + "vct",         claims, "vct");

        if (isPid) {
            String givenName = claimStr(claims, "given_name");
            if (givenName != null) user.setFirstName(givenName);

            String familyName = claimStr(claims, "family_name");
            if (familyName != null) user.setLastName(familyName);

            String email = claimStr(claims, "email");
            if (email != null) {
                user.setEmail(email);
                user.setEmailVerified(true);
            }
        } else {
            if (user.getFirstName() == null || user.getFirstName().isEmpty()) {
                String givenName = claimStr(claims, "given_name");
                if (givenName != null) user.setFirstName(givenName);
            }
            if (user.getLastName() == null || user.getLastName().isEmpty()) {
                String familyName = claimStr(claims, "family_name");
                if (familyName != null) user.setLastName(familyName);
            }
        }

        if (isPid) {
            setAttrIfPresent(user, "pid_unique_id",      claims, "unique_id");
            setAttrIfPresent(user, "pid_birth_date",     claims, "birth_date", "birthdate");
            setAttrIfPresent(user, "pid_birth_place",    claims, "birth_place");
            setAttrIfPresent(user, "pid_issuing_country",claims, "issuing_country");
            setAttrIfPresent(user, "pid_age_in_years",   claims, "age_in_years");
        }

        if (!isPid) {
            setAttrIfPresent(user, "diploma_student_id",      claims, "student_id", "studentId");
            setAttrIfPresent(user, "diploma_university",      claims, "university");
            setAttrIfPresent(user, "diploma_graduation_year", claims, "graduation_year", "graduationYear");
            setAttrIfPresent(user, "diploma_is_student",      claims, "is_student", "isStudent");
            setAttrIfPresent(user, "diploma_issuing_country", claims, "issuing_country");
            setAttrIfPresent(user, "diploma_issuance_date",   claims, "issuance_date");
            setAttrIfPresent(user, "diploma_expiry_date",     claims, "expiry_date");
        }

        user.setSingleAttribute("last_" + prefix + "auth", String.valueOf(System.currentTimeMillis()));
        user.setSingleAttribute("auth_method", "eudi_wallet");

        LOG.infof("Updated %s attributes for user. firstName=%s, lastName=%s",
                  credentialType, maskPii(user.getFirstName()), maskPii(user.getLastName()));
    }

    /**
     * Seteaza un atribut Keycloak din primul claim gasit in lista (ignorate daca lipsesc).
     */
    private static void setAttrIfPresent(UserModel user, String attrName,
                                          Map<String, Object> claims, String... claimNames) {
        for (String claimName : claimNames) {
            Object val = claims.get(claimName);
            if (val != null) {
                user.setSingleAttribute(attrName, String.valueOf(val));
                return;
            }
        }
    }

    /** Returneaza valoarea unui claim ca String, sau null daca lipseste. */
    private static String claimStr(Map<String, Object> claims, String key) {
        Object val = claims.get(key);
        return val != null ? String.valueOf(val) : null;
    }

    /** Citeste o valoare String din configuratia authenticatorului, cu fallback la default. */
    private static String cfgString(AuthenticatorConfigModel cfg, String key, String defaultValue) {
        if (cfg == null || cfg.getConfig() == null) return defaultValue;
        String val = cfg.getConfig().get(key);
        return (val != null && !val.isBlank()) ? val : defaultValue;
    }

    /** Citeste o valoare int din configuratia authenticatorului, cu fallback la default. */
    private static int cfgInt(AuthenticatorConfigModel cfg, String key, int defaultValue) {
        String val = cfgString(cfg, key, null);
        if (val == null) return defaultValue;
        try { return Integer.parseInt(val.trim()); } catch (NumberFormatException e) { return defaultValue; }
    }

    /** Mascheaza valori PII in log-uri: afiseaza primele 4 caractere urmate de *** */
    private static String maskPii(String value) {
        if (value == null) return "null";
        if (value.length() <= 4) return "***";
        return value.substring(0, 4) + "***";
    }

    /** Mascheaza adrese de email in log-uri: pastreaza doar domeniul */
    private static String maskEmail(String email) {
        if (email == null) return "null";
        int atIdx = email.indexOf('@');
        return atIdx > 0 ? "***" + email.substring(atIdx) : "***";
    }

    /**
     * Genereaza HTML pentru pagina cu QR code
     */
    private String generateQrPageHtml(String authRequestUrl, String state, String callbackUrl) {
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EUDI Wallet Authentication</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .instructions {
            background: #f0f7ff;
            border-left: 4px solid #4285f4;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            border-radius: 5px;
        }
        .instructions ol {
            margin: 10px 0;
            padding-left: 20px;
        }
        .instructions li {
            margin: 8px 0;
        }
        #qr-code {
            margin: 30px auto;
            padding: 20px;
            background: white;
            display: inline-block;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
        }
        .status {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            border-radius: 5px;
            display: none;
        }
        .status.active {
            display: block;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #4285f4;
            border-radius: 50%%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 10px auto;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
        .success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .debug {
            margin-top: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 12px;
            text-align: left;
            font-family: monospace;
            max-height: 150px;
            overflow: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 EUDI Wallet Authentication</h1>
        <p class="subtitle">Scan QR Code with EUDI Wallet</p>

        <div class="instructions">
            <strong>📱 Instructions:</strong>
            <ol>
                <li>Open <strong>EUDI Wallet</strong> on your Android phone</li>
                <li>Tap the <strong>Share document</strong> button or QR scan icon</li>
                <li>Scan the QR code below</li>
                <li>Select your credentials and confirm sharing</li>
            </ol>
        </div>
        
        <div id="qr-code"></div>
        
        <div id="status" class="status">
            <div class="spinner"></div>
            <p>⏳ Waiting for wallet response...</p>
        </div>
        
        <div id="success" class="status success" style="display:none;">
            <p>✅ Authentication successful! Redirecting...</p>
        </div>
        
        <details class="debug">
            <summary style="cursor: pointer; font-weight: bold;">🔧 Debug Info</summary>
            <div style="margin-top: 10px;">
                <p><strong>Callback URL:</strong><br/>%s</p>
                <p><strong>State:</strong> %s</p>
                <p><strong>Auth URL (first 200 chars):</strong><br/>%s...</p>
            </div>
        </details>
    </div>
    
    <script>
        (function() {
            const authRequestUrl = "%s";
            const state = "%s";
            const callbackUrl = "%s";
            
            console.log("=== EUDI Verifier Debug Info ===");
            console.log("Auth Request URL:", authRequestUrl);
            console.log("State:", state);
            console.log("Callback URL:", callbackUrl);
            
            // Generate QR code
            try {
                new QRCode(document.getElementById("qr-code"), {
                    text: authRequestUrl,
                    width: 300,
                    height: 300,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
                
                console.log("✅ QR Code generated successfully");
                
                // Show status after QR is generated
                setTimeout(() => {
                    document.getElementById("status").classList.add("active");
                }, 500);
                
            } catch (error) {
                console.error("❌ Error generating QR code:", error);
                alert("Error generating QR code: " + error.message);
            }
            
            // Polling for authentication status
            let pollAttempts = 0;
            const maxPollAttempts = 60; // 5 minutes
            
            const pollInterval = setInterval(async () => {
                pollAttempts++;
                
                console.log(`Polling attempt ${pollAttempts}/${maxPollAttempts}`);
                
                if (pollAttempts >= maxPollAttempts) {
                    clearInterval(pollInterval);
                    console.log("❌ Polling timeout");
                    alert("Timeout: No authentication received. Please try again.");
                    return;
                }
                
                try {
                    const statusUrl = callbackUrl.replace('/callback', '/status') + '?state=' + encodeURIComponent(state);
                    const response = await fetch(statusUrl, {
                        method: 'GET',
                        headers: { 
                            'Accept': 'application/json',
                            'ngrok-skip-browser-warning': 'true'
                        }
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        if (data.authenticated === true) {
                            console.log("✅ Authentication successful!");
                            clearInterval(pollInterval);
                            
                            document.getElementById("status").style.display = "none";
                            document.getElementById("success").style.display = "block";
                            
                            // Forteaza reincarcarea paginii pentru a declansa authenticate() din nou
                            console.log("Reloading page to complete authentication...");
                            console.log("Current URL:", window.location.href);
                            
                            // Folosim location.href pentru a forta refresh complet
                            // setTimeout pentru a permite userului sa vada mesajul
                            setTimeout(function() {
                                console.log("Executing reload NOW");
                                try {
                                    // incercam mai multe metode
                                    window.location.href = window.location.href;
                                } catch(e) {
                                    console.error("Reload failed:", e);
                                    window.location.reload(true);
                                }
                            }, 1000);
                        }
                    }
                } catch (error) {
                    console.error("Polling error:", error);
                }
            }, 5000); // Poll every 5 seconds
            
            window.addEventListener('beforeunload', () => {
                clearInterval(pollInterval);
            });
        })();
    </script>
</body>
</html>
""".formatted(
                escapeHtml(callbackUrl),
                escapeHtml(state),
                escapeHtml(authRequestUrl.substring(0, Math.min(200, authRequestUrl.length()))),
                escapeJavaScript(authRequestUrl),
                escapeJavaScript(state),
                escapeJavaScript(callbackUrl)
        );
    }
    
    /**
     * Escape HTML pentru a preveni XSS
     */
    private String escapeHtml(String str) {
        return str.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#39;");
    }
    
    /**
     * Escape JavaScript string
     */
    private String escapeJavaScript(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("'", "\\'")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r");
    }
    
    @Override
    public boolean requiresUser() { return false; }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}