package com.license.eudi.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jboss.logging.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Construieste Request Objects ca JWT-uri semnate conform OpenID4VP 1.0
 * EUDI Android wallet suporta doar ECDSA (ES256) pentru semnarea JAR-ului
 *
 * Cheia EC P-256 este persistenta pe disc
 * Calea fisierului: EUDI_VERIFIER_KEY_PATH env var (default: /opt/keycloak/data/eudi-verifier-ec-key.json)
 */
public class RequestObjectJwtBuilder {

    private static final Logger LOG = Logger.getLogger(RequestObjectJwtBuilder.class);

    private static final String DEFAULT_KEY_PATH = "/opt/keycloak/data/eudi-verifier-ec-key.json";

    private static ECKey ecKey;
    private static JWSSigner signer;

    static {
        try {
            ecKey = loadOrGenerateKey();
            signer = new ECDSASigner(ecKey);
        } catch (Exception e) {
            LOG.error("Failed to initialize EC key pair — verifier will not be able to sign requests", e);
        }
    }

    private static ECKey loadOrGenerateKey() throws Exception {
        String keyPath = System.getenv("EUDI_VERIFIER_KEY_PATH");
        if (keyPath == null || keyPath.isBlank()) {
            keyPath = DEFAULT_KEY_PATH;
        }

        Path path = Paths.get(keyPath);

        if (Files.exists(path)) {
            try {
                String json = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
                ECKey loaded = ECKey.parse(json);
                LOG.infof("EC P-256 key loaded from disk: %s (kid=%s)", path, loaded.getKeyID());
                return loaded;
            } catch (Exception e) {
                LOG.errorf("Failed to load EC key from %s: %s — generating a new key", path, e.getMessage());
            }
        }

        ECKey generated = new ECKeyGenerator(Curve.P_256)
            .keyID(UUID.randomUUID().toString())
            .generate();

        try {
            Files.createDirectories(path.getParent());
            Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
            Files.write(tmp, generated.toJSONString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            LOG.infof("EC P-256 key generated and saved to disk: %s (kid=%s)", path, generated.getKeyID());
        } catch (Exception e) {
            LOG.errorf("Could not save EC key to %s: %s — key will be ephemeral this session", path, e.getMessage());
        }

        return generated;
    }

    /**
     * Construieste un Request Object JWT semnat cu ES256
     *
     * @param clientId URL-ul verifier-ului (callback URL)
     * @param responseUri URL pentru VP Token callback
     * @param nonce Nonce pentru replay protection
     * @param state State pentru session tracking
     * @param presentationDefinitionJson Presentation Definition ca String JSON
     * @return JWT semnat ca String
     */
    public static String buildSignedRequestObject(
            String clientId,
            String responseUri,
            String nonce,
            String state,
            String presentationDefinitionJson) throws Exception {

        // JWT Header cu ES256
        // EUDI wallet requires typ=oauth-authz-req+jwt (RFC 9101 / OpenID4VP spec)
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(ecKey.getKeyID())
            .type(new JOSEObjectType("oauth-authz-req+jwt"))
            .build();

        // Claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(clientId)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
            .jwtID(UUID.randomUUID().toString())
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", clientId)
            .claim("client_id_scheme", "pre-registered")
            .claim("response_uri", responseUri)
            .claim("nonce", nonce)
            .claim("state", state)
            .claim("dcql_query", parseJsonToObject(presentationDefinitionJson))
            .claim("client_metadata", buildClientMetadata())
            .build();

        // Semneaza
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();
        LOG.infof("Created signed Request Object JWT (ES256): length=%d, kid=%s", jwt.length(), ecKey.getKeyID());

        return jwt;
    }

    /**
     * Parseaza JSON string in Map pentru claims
     */
    private static Object parseJsonToObject(String json) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            return mapper.readValue(json, Object.class);
        } catch (Exception e) {
            LOG.error("Failed to parse presentation_definition JSON", e);
            throw new RuntimeException("Invalid presentation_definition JSON", e);
        }
    }

    /**
     * Construieste client_metadata pentru EUDI wallet:
     * - jwks: cheia publica EC a verifier-ului
     * - vp_formats: formatele VP acceptate
     */
    private static Map<String, Object> buildClientMetadata() {
        Map<String, Object> clientMetadata = new LinkedHashMap<>();

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", Collections.singletonList(ecKey.toPublicJWK().toJSONObject()));
        clientMetadata.put("jwks", jwks);

        Map<String, Object> vpFormats = new LinkedHashMap<>();
        Map<String, Object> dcSdJwtFormat = new LinkedHashMap<>();
        dcSdJwtFormat.put("sd-jwt_alg_values", Arrays.asList("ES256", "ES384", "ES512", "RS256"));
        dcSdJwtFormat.put("kb-jwt_alg_values", Arrays.asList("ES256", "ES384", "ES512", "RS256"));
        vpFormats.put("dc+sd-jwt", dcSdJwtFormat);
        clientMetadata.put("vp_formats_supported", vpFormats);

        return clientMetadata;
    }

    /**
     * Returneaza cheia publica EC pentru JWKS endpoint
     */
    public static ECKey getPublicKey() {
        return ecKey.toPublicJWK();
    }
}
