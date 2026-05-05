package com.license.eudi.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory pentru EudiVerifierResourceProvider
 * Înregistrează endpoint-urile /realms/{realm}/eudi-verifier/*
 */
public class EudiVerifierResourceProviderFactory implements RealmResourceProviderFactory {
    
    public static final String ID = "eudi-verifier";
    
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new EudiVerifierResourceProvider(session);
    }
    
    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }
    
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-init needed
    }
    
    @Override
    public void close() {
        // Nothing to close
    }
    
    @Override
    public String getId() {
        return ID;
    }
}
