package com.license.eudi.openid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;

/**
 * Builder pentru generarea DCQL (Digital Credentials Query Language) queries
 * conform OpenID4VP Draft 23+ folosit de EUDI Android Wallet (eudi-lib-jvm-openid4vp-kt 0.12+)
 *
 * DCQL inlocuieste Presentation Exchange presentation_definition.
 * Structura: { "credentials": [ { "id", "format": "dc+sd-jwt", "meta": { "vct_values": [...] }, "claims": [...] } ] }
 */
public class PresentationDefinitionBuilder {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Genereaza DCQL query pentru credentiale PID in format SD-JWT (dc+sd-jwt)
     */
    public static String buildPidPresentationDefinition() {
        Map<String, Object> dcqlQuery = new LinkedHashMap<>();

        List<Map<String, Object>> credentials = new ArrayList<>();
        credentials.add(buildPidCredentialQuery());
        dcqlQuery.put("credentials", credentials);

        try {
            return MAPPER.writeValueAsString(dcqlQuery);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize DCQL query", e);
        }
    }

    /**
     * Genereaza un DCQL query pentru credentiale de diploma universitara
     */
    public static String buildDiplomaPresentationDefinition() {
        Map<String, Object> dcqlQuery = new LinkedHashMap<>();

        List<Map<String, Object>> credentials = new ArrayList<>();
        credentials.add(buildDiplomaCredentialQuery());
        dcqlQuery.put("credentials", credentials);

        try {
            return MAPPER.writeValueAsString(dcqlQuery);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize diploma DCQL query", e);
        }
    }

    private static Map<String, Object> buildPidCredentialQuery() {
        Map<String, Object> cred = new LinkedHashMap<>();
        cred.put("id", "pid-credential");
        cred.put("format", "dc+sd-jwt");

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("vct_values", Collections.singletonList("urn:eu.europa.ec.eudi:pid:1"));
        cred.put("meta", meta);

        List<Map<String, Object>> claims = new ArrayList<>();
        claims.add(buildClaim("given_name"));
        claims.add(buildClaim("family_name"));
        claims.add(buildClaim("birth_date"));
        claims.add(buildClaim("birth_place"));
        cred.put("claims", claims);

        return cred;
    }

    private static Map<String, Object> buildDiplomaCredentialQuery() {
        Map<String, Object> cred = new LinkedHashMap<>();
        cred.put("id", "diploma-credential");
        cred.put("format", "dc+sd-jwt");

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("vct_values", Collections.singletonList("urn:org:certsign:university:graduation:1"));
        cred.put("meta", meta);

        List<Map<String, Object>> claims = new ArrayList<>();
        claims.add(buildClaim("given_name"));
        claims.add(buildClaim("family_name"));
        claims.add(buildClaim("student_id"));
        claims.add(buildClaim("university"));
        claims.add(buildClaim("graduation_year"));
        claims.add(buildClaim("is_student"));
        claims.add(buildClaim("issuing_country"));
        claims.add(buildClaim("issuance_date"));
        claims.add(buildClaim("expiry_date"));
        cred.put("claims", claims);

        return cred;
    }

    private static Map<String, Object> buildClaim(String fieldName) {
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("path", Collections.singletonList(fieldName));
        return claim;
    }
}
