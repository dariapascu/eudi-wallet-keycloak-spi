package com.license.eudi.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Provider pentru REST endpoints custom (request URI si callback)
 */
public class EudiVerifierResourceProvider implements RealmResourceProvider {
    
    private final KeycloakSession session;
    
    public EudiVerifierResourceProvider(KeycloakSession session) {
        this.session = session;
    }
    
    @Override
    public Object getResource() {
        return new EudiVerifierResource(session);
    }
    
    @Override
    public void close() {
    }
}
