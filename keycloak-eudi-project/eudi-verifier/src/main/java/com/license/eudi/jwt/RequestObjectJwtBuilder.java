package com.license.eudi.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jboss.logging.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;


public class RequestObjectJwtBuilder {

    private static final Logger LOG = Logger.getLogger(RequestObjectJwtBuilder.class);

    private static final String DEFAULT_SERVER_KEY = "/opt/keycloak/data/eudi-certs/server.key";
    private static final String DEFAULT_SERVER_CRT = "/opt/keycloak/data/eudi-certs/server.crt";
    private static final String DEFAULT_CA_CRT     = "/opt/keycloak/data/eudi-ca/ca.crt";

    private static ECKey ecKey;
    private static JWSSigner signer;
    private static List<Base64> x5cChain;

    static {
        try {
            loadFromNginxCerts();
        } catch (Exception e) {
            LOG.error("Failed to load nginx TLS key/cert — verifier will not be able to sign requests", e);
        }
    }

    private static void loadFromNginxCerts() throws Exception {
        String keyPath  = envOrDefault("EUDI_SERVER_KEY_PATH", DEFAULT_SERVER_KEY);
        String crtPath  = envOrDefault("EUDI_SERVER_CRT_PATH", DEFAULT_SERVER_CRT);
        String caPath   = envOrDefault("EUDI_CA_CRT_PATH",     DEFAULT_CA_CRT);

        // Load PKCS#8 EC private key
        String pemKey = new String(Files.readAllBytes(Paths.get(keyPath)), StandardCharsets.UTF_8);
        String b64Key = pemKey
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = java.util.Base64.getDecoder().decode(b64Key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(keySpec);

        // Load server certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert;
        try (InputStream in = new FileInputStream(crtPath)) {
            serverCert = (X509Certificate) cf.generateCertificate(in);
        }
        ECPublicKey publicKey = (ECPublicKey) serverCert.getPublicKey();

        // Load CA certificate
        X509Certificate caCert;
        try (InputStream in = new FileInputStream(caPath)) {
            caCert = (X509Certificate) cf.generateCertificate(in);
        }

        // Build ECKey with cert chain
        ecKey = new ECKey.Builder(Curve.P_256, publicKey)
            .privateKey(privateKey)
            .build();

        signer = new ECDSASigner(ecKey);

        // x5c chain: server cert first, then CA cert
        x5cChain = Arrays.asList(
            Base64.encode(serverCert.getEncoded()),
            Base64.encode(caCert.getEncoded())
        );

        LOG.infof("Loaded nginx TLS key+cert for JAR signing (X509SanDns): key=%s, cert=%s, ca=%s",
            keyPath, crtPath, caPath);
    }

    private static String envOrDefault(String name, String def) {
        String v = System.getenv(name);
        return (v != null && !v.isBlank()) ? v : def;
    }


    public static String buildSignedRequestObject(
            String clientId,
            String responseUri,
            String nonce,
            String state,
            String presentationDefinitionJson) throws Exception {

        // JWT Header cu x5c — wallet-ul citeste cheia publica din certificat
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType("oauth-authz-req+jwt"))
            .x509CertChain(x5cChain)
            .build();

        // clientId contine deja prefixul: "x509_hash:<hash>"
        // SDK-ul compara client_id din QR URL cu cel din JWT — trebuie sa fie identice
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(clientId)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
            .jwtID(UUID.randomUUID().toString())
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", clientId)
            .claim("client_id_scheme", "x509_hash")
            .claim("response_uri", responseUri)
            .claim("nonce", nonce)
            .claim("state", state)
            .claim("dcql_query", parseJsonToObject(presentationDefinitionJson))
            .claim("client_metadata", buildClientMetadata())
            .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();
        LOG.infof("Created signed Request Object JWT (ES256, x509_san_dns): length=%d", jwt.length());

        return jwt;
    }

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
     * client_metadata fara jwks — cu X509SanDns wallet-ul citeste cheia din x5c header.
     */
    private static Map<String, Object> buildClientMetadata() {
        Map<String, Object> clientMetadata = new LinkedHashMap<>();

        Map<String, Object> vpFormats = new LinkedHashMap<>();
        Map<String, Object> dcSdJwtFormat = new LinkedHashMap<>();
        dcSdJwtFormat.put("sd-jwt_alg_values", Arrays.asList("ES256", "ES384", "ES512", "RS256"));
        dcSdJwtFormat.put("kb-jwt_alg_values", Arrays.asList("ES256", "ES384", "ES512", "RS256"));
        vpFormats.put("dc+sd-jwt", dcSdJwtFormat);
        clientMetadata.put("vp_formats_supported", vpFormats);

        return clientMetadata;
    }

    /**
     * Returneaza cheia publica EC pentru JWKS endpoint (backward compat).
     */
    public static ECKey getPublicKey() {
        return ecKey != null ? ecKey.toPublicJWK() : null;
    }
}
