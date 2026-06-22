package com.license.eudi.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;


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
