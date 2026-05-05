package com.license.eudi.resource;

import com.license.eudi.jwt.RequestObjectJwtBuilder;
import com.license.eudi.jwt.VpTokenValidator;
import com.license.eudi.openid4vp.RequestObjectManager;
import com.license.eudi.session.SessionStateManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST endpoints pentru OpenID4VP:
 * - GET /request/{id} - returneaza Request Object (pentru wallet)
 * - POST /callback - primeste VP Token de la wallet
 */
@Path("/")
public class EudiVerifierResource {
    
    private static final Logger LOG = Logger.getLogger(EudiVerifierResource.class);
    private final KeycloakSession session;
    
    public EudiVerifierResource(KeycloakSession session) {
        this.session = session;
    }
    
    /**
     * Endpoint pentru Request Object by-reference
     * Wallet face GET la acest endpoint pentru a obtine detaliile presentation request-ului
     */
    @GET
    @Path("/request/{requestId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequestObject(@PathParam("requestId") String requestId) {
        LOG.infof("Request Object requested: %s", requestId);
        
        RequestObjectManager.RequestObject data = RequestObjectManager.getInstance().getRequestObject(requestId);
        
        if (data == null) {
            LOG.warnf("Request Object not found: %s", requestId);
            return Response.status(Response.Status.NOT_FOUND)
                .entity(errorJson("invalid_request", "Request Object not found or expired"))
                .build();
        }
        
        try {
            String signedJwt = RequestObjectJwtBuilder.buildSignedRequestObject(
                data.clientId,  // client_id = stable pre-registered identifier
                data.responseUri,
                data.nonce,
                data.state,
                data.presentationDefinition
            );
            
            LOG.infof("Returning signed Request Object JWT for requestId=%s, state=%s, length=%d", 
                requestId, data.state, signedJwt.length());
            
            return Response.ok(signedJwt)
                .type("application/jwt")
                .build();
                
        } catch (Exception e) {
            LOG.error("Failed to create signed Request Object JWT", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(errorJson("server_error", "Failed to create Request Object"))
                .build();
        }
    }
    
    /**
     * JWKS endpoint - expune cheia publica a verifier-ului
     * EUDI wallet poate folosi acest endpoint pentru a verifica semnatura Request Object JWT
     */
    @GET
    @Path("/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJwks() {
        try {
            java.util.Map<String, Object> jwks = new java.util.HashMap<>();
            jwks.put("keys", java.util.Collections.singletonList(
                RequestObjectJwtBuilder.getPublicKey().toJSONObject()
            ));
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            return Response.ok(mapper.writeValueAsString(jwks))
                .header("Access-Control-Allow-Origin", "*")
                .build();
        } catch (Exception e) {
            LOG.error("Failed to serialize JWKS", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * CORS preflight handler pentru /status endpoint
     */
    @OPTIONS
    @Path("/status")
    public Response statusPreflight() {
        return Response.ok()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Accept, ngrok-skip-browser-warning")
            .header("Access-Control-Max-Age", "3600")
            .build();
    }
    
    /**
     * Status endpoint pentru polling din browser
     * Browser verifica periodic daca wallet-ul a trimis VP Token
     */
    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response checkAuthenticationStatus(@QueryParam("state") String state) {
        LOG.infof("Status check requested for state: %s", state);
        
        if (state == null || state.isEmpty()) {
            LOG.warn("Missing state parameter in status check");
            return Response.status(Response.Status.BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, Accept, ngrok-skip-browser-warning")
                .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing state\"}")
                .build();
        }
        
        SessionStateManager.SessionData sessionData = SessionStateManager.getInstance().getSessionData(state);
        
        if (sessionData == null) {
            LOG.warnf("Session data not found for state: %s", state);
            return Response.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, Accept, ngrok-skip-browser-warning")
                .entity("{\"authenticated\":false,\"status\":\"not_found\"}")
                .build();
        }
        
        if (sessionData.isAuthenticated()) {
            LOG.infof("State %s is authenticated", state);
            try {
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("authenticated", true);
                resp.put("status", "success");
                resp.put("vp_received_at", sessionData.getVpReceivedAt());
                resp.put("validated_at", sessionData.getValidatedAt());
                return Response.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, OPTIONS")
                    .header("Access-Control-Allow-Headers", "Content-Type, Accept, ngrok-skip-browser-warning")
                    .entity(new ObjectMapper().writeValueAsString(resp))
                    .build();
            } catch (Exception e) {
                LOG.error("Failed to serialize status response", e);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        }
        
        return Response.ok()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Accept, ngrok-skip-browser-warning")
            .entity("{\"authenticated\":false,\"status\":\"pending\"}")
            .build();
    }
    
    /**
     * Callback endpoint pentru VP Token
     * Wallet face POST aici cu vp_token si presentation_submission
     */
    @POST
    @Path("/callback")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response handleVpToken(
            @FormParam("vp_token") String vpToken,
            @FormParam("presentation_submission") String presentationSubmission,
            @FormParam("state") String state) {
        
        LOG.infof("VP Token received: state=%s, vpToken length=%d", 
            state, vpToken != null ? vpToken.length() : 0);
        
        if (state == null || state.isEmpty()) {
            LOG.warn("Missing state parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorJson("invalid_request", "Missing state"))
                .build();
        }

        if (vpToken == null || vpToken.isEmpty()) {
            LOG.warn("Missing vp_token parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorJson("invalid_request", "Missing vp_token"))
                .build();
        }

        // Obtine session data pentru a prelua nonce
        SessionStateManager.SessionData sessionData = SessionStateManager.getInstance().getSessionData(state);
        if (sessionData == null) {
            LOG.warnf("No session data found for state: %s", state);
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorJson("invalid_request", "Invalid state"))
                .build();
        }

        // Benchmark
        SessionStateManager.getInstance().setVpReceivedAt(state, System.currentTimeMillis());
        
        String expectedNonce = sessionData.getNonce();
        String expectedAudience = sessionData.getClientId();
        LOG.infof("Validating VP Token with expected nonce: %s, KB-JWT expected audience (client_id): %s",
                expectedNonce, expectedAudience);

        String sdJwtToken = extractSdJwtFromDcqlVpToken(vpToken);

        long kbJwtMaxAgeMs = sessionData.getKbJwtMaxAgeMs();
        VpTokenValidator.ValidationResult validationResult = VpTokenValidator.validate(
            sdJwtToken,
            expectedNonce,
            expectedAudience,
            kbJwtMaxAgeMs
        );
        
        if (!validationResult.isValid()) {
            LOG.errorf("VP Token validation failed: %s", validationResult.getErrorMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorJson("invalid_vp_token", validationResult.getErrorMessage()))
                .build();
        }
        
        LOG.info("VP Token fully verified: JWT signature + SD-JWT disclosures + KB-JWT nonce + KB-JWT audience ✓");

        Map<String, Object> claims = validationResult.getClaims();
        String expectedVct = sessionData.getExpectedVct();
        if (expectedVct != null) {
            String receivedVct = claims.get("vct") != null ? String.valueOf(claims.get("vct")) : null;
            if (receivedVct == null) {
                LOG.errorf("VP Token missing 'vct' claim — expected: %s", expectedVct);
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_vp_token", "Credential type (vct) missing from token"))
                    .build();
            }
            if (!expectedVct.equals(receivedVct)) {
                LOG.errorf("VP Token vct mismatch: expected=%s, received=%s", expectedVct, receivedVct);
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_vp_token", "Credential type mismatch: expected " + expectedVct))
                    .build();
            }
            LOG.infof("VCT validated: %s ✓", receivedVct);
        }
        
        if (claims.isEmpty()) {
            LOG.warn("No claims extracted from VP Token");
        }
        
        Map<String, Object> enrichedClaims = enrichClaims(claims);
        
        // Benchmark
        long validatedAt = System.currentTimeMillis();

        SessionStateManager.getInstance().markAuthenticated(state, enrichedClaims, validatedAt);
        
        LOG.infof("Authentication successful for state: %s, extracted %d claims", 
                  state, enrichedClaims.size());
        
        return Response.ok("{\"redirect_uri\":\"about:blank\"}").build();
    }
    
    /**
     * Extrage SD-JWT string din DCQL vp_token JSON object.
     * Format DCQL: {"credential-id": ["<SD-JWT>"]}
     * Daca vp_token nu este JSON sau structura nu corespunde, returneaza tokenul brut
     * si logeaza un warning
     */
    private String extractSdJwtFromDcqlVpToken(String vpToken) {
        if (!vpToken.trim().startsWith("{")) {
            return vpToken;
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> vpTokenMap = mapper.readValue(vpToken, Map.class);
            for (Map.Entry<String, Object> entry : vpTokenMap.entrySet()) {
                Object value = entry.getValue();
                if (!(value instanceof java.util.List)) {
                    LOG.warnf("DCQL vp_token key '%s' has unexpected value type: %s",
                            entry.getKey(), value == null ? "null" : value.getClass().getName());
                    continue;
                }
                java.util.List<?> list = (java.util.List<?>) value;
                if (list.isEmpty()) {
                    LOG.warnf("DCQL vp_token key '%s' has empty list", entry.getKey());
                    continue;
                }
                Object first = list.get(0);
                if (!(first instanceof String)) {
                    LOG.warnf("DCQL vp_token key '%s' first element is not a String: %s",
                            entry.getKey(), first == null ? "null" : first.getClass().getName());
                    continue;
                }
                String sdJwt = (String) first;
                LOG.infof("Extracted SD-JWT from DCQL vp_token key '%s', length=%d", entry.getKey(), sdJwt.length());
                return sdJwt;
            }
            LOG.warn("DCQL vp_token JSON had no valid credential entries");
        } catch (Exception e) {
            LOG.warnf("Failed to parse vp_token as DCQL JSON: %s", e.getMessage());
        }
        return vpToken;
    }

    /**
     * Serializeaza sigur un error response ca JSON, fara concatenare de string-uri.
     * Previne JSON injection daca mesajul de eroare contine caractere speciale.
     */
    private String errorJson(String error, String description) {
        try {
            Map<String, String> body = new LinkedHashMap<>();
            body.put("error", error);
            body.put("error_description", description);
            return new ObjectMapper().writeValueAsString(body);
        } catch (Exception e) {
            return "{\"error\":\"server_error\"}";
        }
    }


    private Map<String, Object> enrichClaims(Map<String, Object> claims) {
        Map<String, Object> enriched = new java.util.HashMap<>(claims);
        
        String[] desiredClaims = {
            "sub", "given_name", "family_name", "email", "birth_date", "birthdate",
            "unique_id", "age_in_years", "ageInYears", "is_over_18", "isOver18",
            "issuing_country", "issuingCountry", "expiry_date", "expiration_date", "valid_until",
            "vct", "firstName", "lastName", "studentId", "student_id",
            "university", "graduationYear", "graduation_year",
            "isStudent", "is_student", "issuance_date",
            "certificate_type"
        };
        
        if (claims.containsKey("credentialSubject")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> credentialSubject = (Map<String, Object>) claims.get("credentialSubject");
            for (String claimName : desiredClaims) {
                if (credentialSubject.containsKey(claimName) && credentialSubject.get(claimName) != null) {
                    enriched.put(claimName, credentialSubject.get(claimName));
                }
            }
        }
        
        return enriched;
    }
    

    @Deprecated
    private Map<String, Object> extractClaimsFromVpToken(String vpToken) {
        Map<String, Object> claims = new java.util.HashMap<>();
        
        try {
            String[] parts = vpToken.split("~");
            String jwtPart = parts[0];
            
            String[] jwtParts = jwtPart.split("\\.");
            if (jwtParts.length < 2) {
                LOG.warn("Invalid JWT format in VP Token");
                return claims;
            }
            
            String payloadJson = new String(
                java.util.Base64.getUrlDecoder().decode(jwtParts[1]),
                java.nio.charset.StandardCharsets.UTF_8
            );
            
            LOG.infof("VP Token payload parsed (length=%d)", payloadJson.length());
            
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = mapper.readValue(payloadJson, Map.class);
            
            extractClaim(claims, payload, "sub");
            extractClaim(claims, payload, "given_name");
            extractClaim(claims, payload, "family_name");
            extractClaim(claims, payload, "email");
            extractClaim(claims, payload, "birth_date");
            extractClaim(claims, payload, "birthdate");
            extractClaim(claims, payload, "unique_id");
            extractClaim(claims, payload, "age_in_years");
            extractClaim(claims, payload, "ageInYears");
            extractClaim(claims, payload, "is_over_18");
            extractClaim(claims, payload, "isOver18");
            extractClaim(claims, payload, "issuing_country");
            extractClaim(claims, payload, "issuingCountry");
            extractClaim(claims, payload, "expiry_date");
            extractClaim(claims, payload, "expiration_date");
            extractClaim(claims, payload, "valid_until");
            
            extractClaim(claims, payload, "vct");
            extractClaim(claims, payload, "firstName");
            extractClaim(claims, payload, "lastName");
            extractClaim(claims, payload, "studentId");
            extractClaim(claims, payload, "university");
            extractClaim(claims, payload, "graduationYear");
            extractClaim(claims, payload, "isStudent");
            extractClaim(claims, payload, "student_id");
            extractClaim(claims, payload, "graduation_year");
            extractClaim(claims, payload, "is_student");
            extractClaim(claims, payload, "issuance_date");
            extractClaim(claims, payload, "expiry_date");
            extractClaim(claims, payload, "expiration_date");
            extractClaim(claims, payload, "valid_until");
            extractClaim(claims, payload, "certificate_type");
            extractClaim(claims, payload, "issuing_country");
            
            if (payload.containsKey("credentialSubject")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> credentialSubject = (Map<String, Object>) payload.get("credentialSubject");
                extractClaim(claims, credentialSubject, "given_name");
                extractClaim(claims, credentialSubject, "family_name");
                extractClaim(claims, credentialSubject, "email");
                extractClaim(claims, credentialSubject, "birthdate");
                extractClaim(claims, credentialSubject, "birth_date");
                extractClaim(claims, credentialSubject, "age_in_years");
                extractClaim(claims, credentialSubject, "ageInYears");
                extractClaim(claims, credentialSubject, "is_over_18");
                extractClaim(claims, credentialSubject, "isOver18");
                extractClaim(claims, credentialSubject, "issuing_country");
                extractClaim(claims, credentialSubject, "issuingCountry");
                extractClaim(claims, credentialSubject, "expiry_date");
                extractClaim(claims, credentialSubject, "expiration_date");
                extractClaim(claims, credentialSubject, "valid_until");

                extractClaim(claims, credentialSubject, "vct");
                extractClaim(claims, credentialSubject, "firstName");
                extractClaim(claims, credentialSubject, "lastName");
                extractClaim(claims, credentialSubject, "studentId");
                extractClaim(claims, credentialSubject, "university");
                extractClaim(claims, credentialSubject, "graduationYear");
                extractClaim(claims, credentialSubject, "isStudent");
                extractClaim(claims, credentialSubject, "student_id");
                extractClaim(claims, credentialSubject, "graduation_year");
                extractClaim(claims, credentialSubject, "is_student");
                extractClaim(claims, credentialSubject, "issuance_date");
                extractClaim(claims, credentialSubject, "expiry_date");
                extractClaim(claims, credentialSubject, "expiration_date");
                extractClaim(claims, credentialSubject, "valid_until");
                extractClaim(claims, credentialSubject, "certificate_type");
                extractClaim(claims, credentialSubject, "issuing_country");
            }
            
            if (parts.length > 1) {
                LOG.infof("Found %d SD-JWT disclosures", parts.length - 1);
                
                for (int i = 1; i < parts.length; i++) {
                    if (parts[i].isEmpty()) continue;
                    
                    try {
                        String disclosureJson = new String(
                            java.util.Base64.getUrlDecoder().decode(parts[i]),
                            java.nio.charset.StandardCharsets.UTF_8
                        );
                        
                        LOG.infof("Disclosure %d parsed (length=%d)", i, disclosureJson.length());
                        
                        @SuppressWarnings("unchecked")
                        java.util.List<Object> disclosure = mapper.readValue(disclosureJson, java.util.List.class);
                        
                        if (disclosure.size() >= 3) {
                            String claimName = String.valueOf(disclosure.get(1));
                            Object claimValue = disclosure.get(2);
                            
                            claims.put(claimName, claimValue);
                            LOG.infof("Extracted claim from disclosure: %s = %s", claimName, claimValue);
                        }
                    } catch (Exception e) {
                        LOG.warn("Failed to parse disclosure: " + parts[i], e);
                    }
                }
            }
            
            LOG.infof("Extracted claims: %s", claims.keySet());
            
        } catch (Exception e) {
            LOG.error("Error extracting claims from VP Token", e);
        }
        
        return claims;
    }

    private void extractClaim(Map<String, Object> target, Map<String, Object> source, String key) {
        if (source.containsKey(key) && source.get(key) != null) {
            target.put(key, source.get(key));
        }
    }
}
