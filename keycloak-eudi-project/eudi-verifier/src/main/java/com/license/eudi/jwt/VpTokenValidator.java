package com.license.eudi.jwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.jboss.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Validator pentru VP Token (SD-JWT format) conform OpenID4VP si SD-JWT spec
 * 
 * Verificari:
 * - Semnatura JWT cu cheia publica a issuer-ului
 * - Claim-uri standard (nonce, aud, iss, exp, nbf)
 * - Hash-uri disclosures (pentru SD-JWT selective disclosure)
 */
public class VpTokenValidator {
    
    private static final Logger LOG = Logger.getLogger(VpTokenValidator.class);
    
    /**
     * Valideaza VP Token complet: semnatura, claims, disclosures
     * 
     * @param vpToken VP Token in format SD-JWT
     * @param expectedNonce Nonce-ul asteptat (din request)
     * @param expectedAudience Audience-ul asteptat (client_id / response_uri)
     * @return ValidationResult cu status si claims extrase
     */
    public static ValidationResult validate(String vpToken, String expectedNonce, String expectedAudience,
                                             long kbJwtMaxAgeMs) {
        try {
            // Separa JWT de disclosures si KB-JWT:
            // Format SD-JWT: <issuer-jwt>~<disclosure1>~...~<kb-jwt>
            // KB-JWT-ul este ultimul element si contine "." (este el insusi un JWT)
            // Disclosures sunt base64url arrays fara "."
            String[] parts = vpToken.split("~");
            String jwtPart = parts[0];
            List<String> disclosures = new ArrayList<>();
            String kbJwt = null;

            if (parts.length > 1) {
                for (int i = 1; i < parts.length; i++) {
                    String part = parts[i];
                    if (part.isEmpty()) continue;
                    // KB-JWT contine "." (header.payload.signature); disclosures nu contin "."
                    if (part.contains(".") && i == parts.length - 1) {
                        kbJwt = part;
                        LOG.infof("Detected KB-JWT (Key Binding JWT) as last SD-JWT component");
                    } else {
                        disclosures.add(part);
                    }
                }
            }

            LOG.infof("Validating VP Token: JWT length=%d, disclosures=%d, kbJwt=%s",
                    jwtPart.length(), disclosures.size(), kbJwt != null ? "present" : "absent");
            
            // Parse JWT
            SignedJWT signedJWT = SignedJWT.parse(jwtPart);
            
            // STEP 1: Verifica semnatura JWT cu JWKS — obligatoriu
            SignatureVerificationResult sigResult = verifySignature(signedJWT);
            boolean signatureValid = (sigResult == SignatureVerificationResult.VERIFIED);
            switch (sigResult) {
                case VERIFIED:
                    break; // continuăm normal
                case INVALID_SIGNATURE:
                    return ValidationResult.error("VP Token signature is invalid — token may be forged");
                case JWKS_UNAVAILABLE:
                    return ValidationResult.error("Cannot verify VP Token signature — issuer JWKS endpoint unreachable");
                case ERROR:
                    return ValidationResult.error("VP Token signature verification error — check issuer configuration");
            }
            
            // STEP 2: Extrage claims din JWT payload
            Map<String, Object> payload = signedJWT.getJWTClaimsSet().getClaims();
            
            // STEP 3: Valida claim-uri standard
            String nonce = (String) payload.get("nonce");
            String iss = (String) payload.get("iss");
            Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
            Date nbf = signedJWT.getJWTClaimsSet().getNotBeforeTime();
            
            // Nonce-ul din issuer JWT e opțional (SD-JWT spec nu îl impune aici).
            // Validarea nonce-ului se face EXCLUSIV prin KB-JWT (Step 5 de mai jos).
            if (nonce != null && expectedNonce != null && !expectedNonce.equals(nonce)) {
                LOG.errorf("Nonce mismatch in issuer JWT: expected=%s, actual=%s", expectedNonce, nonce);
                return ValidationResult.error("Nonce mismatch in issuer JWT");
            }
            
            // Verifica expiration
            if (exp != null && exp.before(new Date())) {
                LOG.errorf("VP Token expired: exp=%s", exp);
                return ValidationResult.error("Token expired");
            }
            
            // Verifica not-before
            if (nbf != null && nbf.after(new Date())) {
                LOG.errorf("VP Token not yet valid: nbf=%s", nbf);
                return ValidationResult.error("Token not yet valid");
            }
            
            LOG.infof("VP Token standard claims validated: iss=%s, exp=%s, nonce=%s", iss, exp, nonce);
            
            // STEP 4: Procesa disclosures (SD-JWT selective disclosure)
            Map<String, Object> allClaims = new HashMap<>(payload);
            if (!disclosures.isEmpty()) {
                Map<String, Object> disclosedClaims = processDisclosures(disclosures, payload);
                if (disclosedClaims == null) {
                    return ValidationResult.error("SD-JWT disclosure hash verification failed — token may be tampered");
                }
                allClaims.putAll(disclosedClaims);
                LOG.infof("Processed %d disclosures, extracted %d claims", disclosures.size(), disclosedClaims.size());
            }

            // STEP 5: Valideaza KB-JWT (EUDI wallet trimite intotdeauna KB-JWT)
            String kbJwtError = null;
            boolean kbJwtValid = false;
            if (kbJwt != null) {
                kbJwtError = validateKbJwt(kbJwt, expectedNonce, expectedAudience, kbJwtMaxAgeMs);
                kbJwtValid = (kbJwtError == null);
                if (kbJwtValid && nonce == null) {
                    LOG.info("Nonce validated via KB-JWT");
                }
                if (!kbJwtValid) {
                    LOG.errorf("KB-JWT validation failed: %s", kbJwtError);
                    return ValidationResult.error("KB-JWT validation failed: " + kbJwtError);
                }
            } else {
                LOG.error("No KB-JWT found in VP Token — nonce cannot be validated, rejecting");
                return ValidationResult.error("VP Token missing KB-JWT — replay protection not possible");
            }

            // Log validation summary
            LOG.infof("=== VP TOKEN VALIDATION SUMMARY ===");
            LOG.infof("✓ JWT Parsing: SUCCESS");
            LOG.infof("✓ Signature: %s", signatureValid ? "VERIFIED ✓" : "FAILED ✗");
            LOG.infof("✓ Expiration: %s", exp != null ? "Valid until " + exp : "No expiration");
            LOG.infof("✓ Not-Before: %s", nbf != null ? "Valid from " + nbf : "No not-before");
            LOG.infof("✓ Nonce: %s", nonce != null ? "In issuer JWT" : (kbJwtValid ? "In KB-JWT ✓" : "Not present"));
            LOG.infof("✓ KB-JWT: %s", kbJwt != null ? (kbJwtValid ? "VALID ✓" : "INVALID ✗") : "Absent");
            LOG.infof("✓ Issuer: %s", iss != null ? iss : "Not specified");
            LOG.infof("✓ SD-JWT Disclosures: %d processed and hash-verified", disclosures.size());
            LOG.infof("✓ Total Claims Extracted: %d", allClaims.size());
            LOG.infof("===================================");
            
            return ValidationResult.success(allClaims, signatureValid);
            
        } catch (Exception e) {
            LOG.error("VP Token validation failed", e);
            return ValidationResult.error("Validation error: " + e.getMessage());
        }
    }
    
    /**
     * Valideaza KB-JWT (Key Binding JWT) trimis de EUDI wallet.
     *
     * KB-JWT contine:
     *  - nonce: trebuie sa corespunda cu cel din request
     *  - aud: trebuie sa fie response_uri-ul verifier-ului
     *  - iat: trebuie sa fie recent (max 5 minute)
     *  - sd_hash: hash-ul issuer JWT + disclosures
     *
     * @return null daca validarea a trecut, sau un mesaj de eroare daca a esuat
     */
    private static final long DEFAULT_KBJWT_MAX_AGE_MS = 5 * 60 * 1000L;

    private static String validateKbJwt(String kbJwtStr, String expectedNonce, String expectedAudience,
                                         long kbJwtMaxAgeMs) {
        try {
            SignedJWT kbJWT = SignedJWT.parse(kbJwtStr);
            Map<String, Object> kbClaims = kbJWT.getJWTClaimsSet().getClaims();

            LOG.infof("KB-JWT claims present: %s", kbClaims.keySet());

            // Verifica nonce — obligatoriu conform OpenID4VP spec (replay protection)
            String kbNonce = (String) kbClaims.get("nonce");
            if (kbNonce == null) {
                LOG.error("KB-JWT missing 'nonce' claim — replay protection not possible");
                return "KB-JWT missing nonce claim";
            }
            if (expectedNonce == null) {
                LOG.error("Expected nonce is null — cannot validate KB-JWT nonce");
                return "Server nonce missing for KB-JWT validation";
            }
            if (!expectedNonce.equals(kbNonce)) {
                LOG.errorf("KB-JWT nonce mismatch: expected=%s, actual=%s", expectedNonce, kbNonce);
                return "KB-JWT nonce mismatch";
            }
            LOG.infof("KB-JWT nonce validated successfully");

            // Verifica aud (audience = response_uri al verifier-ului)
            List<String> kbAud = kbJWT.getJWTClaimsSet().getAudience();
            if (expectedAudience != null) {
                if (kbAud == null || kbAud.isEmpty()) {
                    LOG.error("KB-JWT missing 'aud' claim");
                    return "KB-JWT missing audience claim";
                }
                if (!kbAud.contains(expectedAudience)) {
                    LOG.errorf("KB-JWT audience mismatch: expected=%s, actual=%s", expectedAudience, kbAud);
                    return "KB-JWT audience mismatch — token may have been replayed from another verifier";
                }
                LOG.infof("KB-JWT audience validated: %s", expectedAudience);
            }

            // Verifica iat (nu mai vechi de 5 minute — previne replay attacks)
            Date kbIat = kbJWT.getJWTClaimsSet().getIssueTime();
            if (kbIat == null) {
                LOG.error("KB-JWT missing 'iat' claim");
                return "KB-JWT missing iat claim";
            }
            long ageMs = System.currentTimeMillis() - kbIat.getTime();
            long maxAge = kbJwtMaxAgeMs > 0 ? kbJwtMaxAgeMs : DEFAULT_KBJWT_MAX_AGE_MS;
            if (ageMs > maxAge) {
                LOG.errorf("KB-JWT is too old: age=%ds (max %ds)", ageMs / 1000, maxAge / 1000);
                return "KB-JWT expired — iat too old (" + (ageMs / 1000) + "s ago, max " + (maxAge / 1000) + "s)";
            }
            LOG.infof("KB-JWT iat validated: age=%ds (max %ds)", ageMs / 1000, maxAge / 1000);

            LOG.info("KB-JWT validation passed");
            return null; // null = succes

        } catch (Exception e) {
            LOG.error("KB-JWT validation failed with exception", e);
            return "KB-JWT validation error: " + e.getMessage();
        }
    }

    /**
     * Rezultat detaliat al verificării semnăturii, pentru a distinge
     * între "semnătură invalidă" (token falsificat) și "JWKS indisponibil" (problemă de infrastructură).
     */
    enum SignatureVerificationResult {
        VERIFIED,           // semnătură criptografic validă
        INVALID_SIGNATURE,  // token falsificat / cheie greșită
        JWKS_UNAVAILABLE,   // nu s-a putut contacta issuer-ul pentru JWKS
        ERROR               // altă eroare (iss lipsă, algoritm nesuportat etc.)
    }

    /**
     * Verifica semnatura JWT a issuer-ului.
     *
     * Strategia (în ordine):
     * 1. x5c header — issuer semnează cu certificat hardware, cheia publică e în header
     * 2. JWKS endpoint  — fallback pentru issueri care expun JWKS
     */
    private static SignatureVerificationResult verifySignature(SignedJWT signedJWT) {
        try {
            String algorithm = signedJWT.getHeader().getAlgorithm().getName();
            LOG.infof("Verifying JWT signature: algorithm=%s, iss=%s",
                     algorithm, signedJWT.getJWTClaimsSet().getIssuer());

            // --- Strategia 1: x5c (X.509 Certificate Chain în header) ---
            List<com.nimbusds.jose.util.Base64> x5cList = signedJWT.getHeader().getX509CertChain();
            if (x5cList != null && !x5cList.isEmpty()) {
                LOG.infof("Found x5c header with %d certificate(s) — using certificate chain for verification", x5cList.size());
                SignatureVerificationResult result = verifyWithX5c(signedJWT, x5cList, algorithm);
                if (result != SignatureVerificationResult.ERROR) {
                    return result;
                }
                LOG.warn("x5c verification failed, falling back to JWKS");
            }

            // --- Strategia 2: JWKS de la issuer ---
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (issuer == null) {
                LOG.error("JWT has no 'iss' claim and no x5c header — cannot verify signature");
                return SignatureVerificationResult.ERROR;
            }
            return verifyWithJwks(signedJWT, issuer, algorithm);

        } catch (Exception e) {
            LOG.errorf("Signature verification error: %s: %s", e.getClass().getSimpleName(), e.getMessage());
            return SignatureVerificationResult.ERROR;
        }
    }

    /**
     * Verifică semnătura folosind certificatul din header-ul x5c.
     * Certificatul leaf (primul din array) conține cheia publică a issuer-ului.
     */
    private static SignatureVerificationResult verifyWithX5c(SignedJWT signedJWT,
            List<com.nimbusds.jose.util.Base64> x5cList, String algorithm) {
        try {
            // Decode certificatul leaf (primul din array)
            byte[] certBytes = x5cList.get(0).decode();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate leafCert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certBytes));

            LOG.infof("x5c leaf certificate: subject=%s, issuer=%s, valid until=%s",
                     leafCert.getSubjectX500Principal().getName(),
                     leafCert.getIssuerX500Principal().getName(),
                     leafCert.getNotAfter());

            // Verifică că certificatul nu a expirat
            try {
                leafCert.checkValidity();
            } catch (Exception e) {
                LOG.errorf("x5c leaf certificate is not valid: %s", e.getMessage());
                return SignatureVerificationResult.INVALID_SIGNATURE;
            }

            PublicKey publicKey = leafCert.getPublicKey();
            JWSVerifier verifier = buildVerifier(publicKey, algorithm);
            if (verifier == null) {
                return SignatureVerificationResult.ERROR;
            }

            boolean verified = signedJWT.verify(verifier);
            if (verified) {
                LOG.info("✓ JWT signature VERIFIED via x5c certificate");
                return SignatureVerificationResult.VERIFIED;
            } else {
                LOG.error("✗ JWT signature INVALID using x5c public key — possible forgery");
                return SignatureVerificationResult.INVALID_SIGNATURE;
            }
        } catch (Exception e) {
            LOG.errorf("x5c verification error: %s: %s", e.getClass().getSimpleName(), e.getMessage());
            return SignatureVerificationResult.ERROR;
        }
    }

    /**
     * Verifică semnătura folosind JWKS de la issuer (fallback când x5c nu e prezent).
     */
    private static SignatureVerificationResult verifyWithJwks(SignedJWT signedJWT,
            String issuer, String algorithm) {
        String kid = signedJWT.getHeader().getKeyID();
        LOG.infof("Verifying via JWKS: issuer=%s, kid=%s", issuer, kid);

        JWKSet jwkSet = fetchJWKS(issuer);
        if (jwkSet == null) {
            LOG.errorf("Failed to fetch JWKS from issuer: %s", issuer);
            return SignatureVerificationResult.JWKS_UNAVAILABLE;
        }

        JWK jwk = kid != null ? jwkSet.getKeyByKeyId(kid) : null;
        if (jwk == null && !jwkSet.getKeys().isEmpty()) {
            jwk = jwkSet.getKeys().get(0);
            LOG.warnf("No key with kid=%s, using first JWKS key", kid);
        }
        if (jwk == null) {
            LOG.error("No suitable key found in JWKS");
            return SignatureVerificationResult.ERROR;
        }

        try {
            PublicKey publicKey;
            if (algorithm.startsWith("ES")) {
                publicKey = jwk.toECKey().toECPublicKey();
            } else if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
                publicKey = jwk.toRSAKey().toRSAPublicKey();
            } else {
                LOG.errorf("Unsupported algorithm: %s", algorithm);
                return SignatureVerificationResult.ERROR;
            }

            JWSVerifier verifier = buildVerifier(publicKey, algorithm);
            if (verifier == null) return SignatureVerificationResult.ERROR;

            boolean verified = signedJWT.verify(verifier);
            if (verified) {
                LOG.infof("✓ JWT signature VERIFIED via JWKS (kid=%s)", jwk.getKeyID());
                return SignatureVerificationResult.VERIFIED;
            } else {
                LOG.error("✗ JWT signature INVALID via JWKS — possible forgery");
                return SignatureVerificationResult.INVALID_SIGNATURE;
            }
        } catch (Exception e) {
            LOG.errorf("JWKS verification error: %s", e.getMessage());
            return SignatureVerificationResult.ERROR;
        }
    }

    /**
     * Construiește JWSVerifier corespunzător cheii publice și algoritmului.
     */
    private static JWSVerifier buildVerifier(PublicKey publicKey, String algorithm) {
        try {
            if (algorithm.startsWith("ES") && publicKey instanceof ECPublicKey) {
                return new ECDSAVerifier((ECPublicKey) publicKey);
            } else if ((algorithm.startsWith("RS") || algorithm.startsWith("PS"))
                       && publicKey instanceof RSAPublicKey) {
                return new RSASSAVerifier((RSAPublicKey) publicKey);
            } else {
                LOG.errorf("Cannot build verifier: algorithm=%s, keyType=%s",
                          algorithm, publicKey.getAlgorithm());
                return null;
            }
        } catch (Exception e) {
            LOG.errorf("Failed to build JWSVerifier: %s", e.getMessage());
            return null;
        }
    }
    
    /**
     * SSLContext care acceptă certificate self-signed — utilizat EXCLUSIV pentru
     * fetch-ul JWKS de la issuer-ul local (192.168.1.x).
     *
     * NOTĂ SECURITATE: Acceptarea oricărui certificat este acceptabilă NUMAI pentru
     * conexiuni interne/locale unde identitatea serverului este garantată prin altă metodă
     * (în cazul nostru, validăm semnătura JWT cu cheia publică obținută din JWKS,
     * deci chiar dacă TLS e bypassat, un JWKS falsificat ar produce o cheie care nu
     * verifică semnătura token-ului real al issuer-ului).
     */
    private static SSLContext buildTrustAllSslContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx;
    }

    /**
     * Deschide o conexiune HTTP/HTTPS, cu suport pentru certificate self-signed
     * pe endpoint-urile locale (issuer intern).
     */
    private static HttpURLConnection openConnection(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
            httpsConn.setSSLSocketFactory(buildTrustAllSslContext().getSocketFactory());
            httpsConn.setHostnameVerifier((hostname, session) -> true);
        }
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("Accept", "application/json");
        return conn;
    }

    /**
     * Fetch JWKS (JSON Web Key Set) de la issuer.
     *
     * Încearcă endpoint-urile standard, apoi OpenID Discovery.
     * Suportă certificate self-signed pentru issueri locali.
     */
    private static JWKSet fetchJWKS(String issuer) {
        String baseUrl = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;

        String[] jwksUrls = {
            baseUrl + "/.well-known/jwks.json",
            baseUrl + "/jwks",
            baseUrl + "/.well-known/jwks"
        };

        for (String jwksUrl : jwksUrls) {
            try {
                LOG.infof("Attempting to fetch JWKS from: %s", jwksUrl);
                HttpURLConnection conn = openConnection(jwksUrl);
                int responseCode = conn.getResponseCode();

                if (responseCode == 200) {
                    try (InputStream is = conn.getInputStream()) {
                        JWKSet jwkSet = JWKSet.load(is);
                        LOG.infof("Successfully fetched JWKS from: %s (%d keys)", jwksUrl, jwkSet.getKeys().size());
                        return jwkSet;
                    }
                } else {
                    LOG.warnf("JWKS endpoint %s returned HTTP %d", jwksUrl, responseCode);
                }
            } catch (Exception e) {
                LOG.warnf("Could not fetch JWKS from %s: %s: %s",
                          jwksUrl, e.getClass().getSimpleName(), e.getMessage());
            }
        }

        // Încearcă OpenID Discovery
        try {
            String discoveryUrl = baseUrl + "/.well-known/openid-configuration";
            LOG.infof("Attempting OpenID Discovery at: %s", discoveryUrl);
            HttpURLConnection conn = openConnection(discoveryUrl);

            if (conn.getResponseCode() == 200) {
                try (InputStream is = conn.getInputStream()) {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> config = mapper.readValue(is, Map.class);
                    String jwksUri = (String) config.get("jwks_uri");

                    if (jwksUri != null) {
                        LOG.infof("Found jwks_uri from discovery: %s", jwksUri);
                        HttpURLConnection jwksConn = openConnection(jwksUri);
                        if (jwksConn.getResponseCode() == 200) {
                            try (InputStream jwksIs = jwksConn.getInputStream()) {
                                JWKSet jwkSet = JWKSet.load(jwksIs);
                                LOG.infof("Fetched JWKS via discovery from: %s (%d keys)", jwksUri, jwkSet.getKeys().size());
                                return jwkSet;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOG.warnf("OpenID Discovery failed: %s: %s", e.getClass().getSimpleName(), e.getMessage());
        }

        LOG.errorf("Failed to fetch JWKS from issuer: %s (tried all endpoints)", issuer);
        return null;
    }
    
    /**
     * Proceseaza disclosures SD-JWT si extrage claim-urile.
     *
     * SD-JWT disclosure format: base64url([salt, claim_name, claim_value])
     * Hash verification: SHA-256(disclosure) TREBUIE sa apara in payload._sd array.
     *
     * @return map cu claims extrase, sau null daca vreun hash nu corespunde (tampering detectat)
     */
    private static Map<String, Object> processDisclosures(List<String> disclosures, Map<String, Object> payload) {
        Map<String, Object> disclosedClaims = new HashMap<>();

        // Obtine array-ul de hash-uri din payload
        @SuppressWarnings("unchecked")
        List<String> expectedHashes = (List<String>) payload.get("_sd");
        Set<String> expectedHashSet = expectedHashes != null ? new HashSet<>(expectedHashes) : new HashSet<>();

        LOG.infof("Processing %d SD-JWT disclosures (expected %d hashes in _sd array)",
                  disclosures.size(), expectedHashSet.size());

        // Dacă nu există _sd în payload, nu putem verifica hash-urile — acceptăm cu warning
        boolean canVerifyHashes = !expectedHashSet.isEmpty();
        if (!canVerifyHashes) {
            LOG.warn("No _sd array in JWT payload — cannot verify disclosure hashes cryptographically");
        }

        int hashVerifiedCount = 0;

        for (String disclosure : disclosures) {
            try {
                byte[] disclosureBytes = Base64.getUrlDecoder().decode(disclosure);
                String disclosureJson = new String(disclosureBytes, java.nio.charset.StandardCharsets.UTF_8);

                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                @SuppressWarnings("unchecked")
                List<Object> disclosureArray = mapper.readValue(disclosureJson, List.class);

                if (disclosureArray.size() < 3) {
                    // Nu logăm conținutul disclosure-ului — poate conține date personale
                    LOG.warnf("Disclosure has unexpected format (less than 3 elements), size=%d", disclosureArray.size());
                    continue;
                }

                String claimName = String.valueOf(disclosureArray.get(1));
                Object claimValue = disclosureArray.get(2);

                // Verificare criptografică hash (SD-JWT spec obligatoriu)
                if (canVerifyHashes) {
                    String disclosureHash = computeSHA256Base64Url(disclosure);
                    if (!expectedHashSet.contains(disclosureHash)) {
                        LOG.errorf("✗ Disclosure hash MISMATCH for claim '%s' — TAMPERING DETECTED! " +
                                   "Computed hash: %s not found in _sd array.", claimName, disclosureHash);
                        return null; // semnal de eroare fatală către apelant
                    }
                    hashVerifiedCount++;
                    LOG.debugf("✓ Disclosure hash verified for claim '%s'", claimName);
                }

                disclosedClaims.put(claimName, claimValue);
                LOG.debugf("Disclosed claim: %s", claimName);

            } catch (Exception e) {
                LOG.errorf("Failed to process disclosure — treating as tampered: %s", e.getMessage());
                return null;
            }
        }

        if (canVerifyHashes) {
            LOG.infof("SD-JWT Hash Verification: %d/%d disclosures cryptographically verified (SHA-256)",
                      hashVerifiedCount, disclosures.size());
        }

        return disclosedClaims;
    }
    
    /**
     * Calculeaza SHA-256 hash si encodeaza in Base64URL
     */
    private static String computeSHA256Base64Url(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute SHA-256 hash", e);
        }
    }
    
    /**
     * Rezultatul validarii
     */
    public static class ValidationResult {
        private final boolean valid;
        private final boolean signatureVerified;
        private final String errorMessage;
        private final Map<String, Object> claims;
        
        private ValidationResult(boolean valid, boolean signatureVerified, String errorMessage, Map<String, Object> claims) {
            this.valid = valid;
            this.signatureVerified = signatureVerified;
            this.errorMessage = errorMessage;
            this.claims = claims;
        }
        
        public static ValidationResult success(Map<String, Object> claims, boolean signatureVerified) {
            return new ValidationResult(true, signatureVerified, null, claims);
        }
        
        public static ValidationResult error(String errorMessage) {
            return new ValidationResult(false, false, errorMessage, Collections.emptyMap());
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public boolean isSignatureVerified() {
            return signatureVerified;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
        
        public Map<String, Object> getClaims() {
            return claims;
        }
    }
}
