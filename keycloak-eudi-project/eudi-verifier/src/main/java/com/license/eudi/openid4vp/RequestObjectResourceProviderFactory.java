package com.license.eudi.openid4vp;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for registering the Request Object REST endpoint with Keycloak
 */
public class RequestObjectResourceProviderFactory implements RealmResourceProviderFactory {
    
    public static final String PROVIDER_ID = "eudi-verifier";
    
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RequestObjectResource(session);
    }
    
    @Override
    public void init(Config.Scope config) {
    }
    
    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }
    
    @Override
    public void close() {
    }
    
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
