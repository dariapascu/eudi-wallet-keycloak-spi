package com.license.eudi;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class EudiVerifierAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "eudi-verifier-authenticator";

    // Config property keys — folosite in EudiVerifierAuthenticator pentru a citi valorile
    public static final String CFG_CLIENT_ID         = "client_id";
    public static final String CFG_PID_VCT           = "pid_vct";
    public static final String CFG_DIPLOMA_VCT       = "diploma_vct";
    public static final String CFG_STATE_TIMEOUT_MIN = "state_timeout_minutes";
    public static final String CFG_KBJWT_MAX_AGE_SEC = "kb_jwt_max_age_seconds";

    // Valori implicite
    public static final String  DEFAULT_PID_VCT           = "urn:eu.europa.ec.eudi:pid:1";
    public static final String  DEFAULT_DIPLOMA_VCT        = "urn:org:certsign:university:graduation:1";
    public static final int     DEFAULT_STATE_TIMEOUT_MIN  = 10;
    public static final int     DEFAULT_KBJWT_MAX_AGE_SEC  = 300;

    @Override
    public String getId() { return PROVIDER_ID; }

    @Override
    public String getDisplayType() { return "EUDI Wallet Verifier (OpenID4VP)"; }

    @Override
    public String getHelpText() { return "Passwordless login via EUDI Wallet and Verifiable Presentation"; }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new EudiVerifierAuthenticator();
    }

    @Override
    public boolean isConfigurable() { return true; }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.ALTERNATIVE
        };
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty clientId = new ProviderConfigProperty();
        clientId.setName(CFG_CLIENT_ID);
        clientId.setLabel("Client ID");
        clientId.setType(ProviderConfigProperty.STRING_TYPE);
        clientId.setHelpText("Identificatorul verifier-ului trimis în QR code. Implicit: <realm>-verifier");
        clientId.setDefaultValue("");

        ProviderConfigProperty pidVct = new ProviderConfigProperty();
        pidVct.setName(CFG_PID_VCT);
        pidVct.setLabel("PID VCT");
        pidVct.setType(ProviderConfigProperty.STRING_TYPE);
        pidVct.setHelpText("Valoarea claim-ului 'vct' așteptată pentru credențiale PID");
        pidVct.setDefaultValue(DEFAULT_PID_VCT);

        ProviderConfigProperty diplomaVct = new ProviderConfigProperty();
        diplomaVct.setName(CFG_DIPLOMA_VCT);
        diplomaVct.setLabel("Diploma VCT");
        diplomaVct.setType(ProviderConfigProperty.STRING_TYPE);
        diplomaVct.setHelpText("Valoarea claim-ului 'vct' așteptată pentru credențiale de diplomă");
        diplomaVct.setDefaultValue(DEFAULT_DIPLOMA_VCT);

        ProviderConfigProperty stateTimeout = new ProviderConfigProperty();
        stateTimeout.setName(CFG_STATE_TIMEOUT_MIN);
        stateTimeout.setLabel("State timeout (minute)");
        stateTimeout.setType(ProviderConfigProperty.STRING_TYPE);
        stateTimeout.setHelpText("Cât timp (minute) este valid un state QR înainte de expirare");
        stateTimeout.setDefaultValue(String.valueOf(DEFAULT_STATE_TIMEOUT_MIN));

        ProviderConfigProperty kbJwtMaxAge = new ProviderConfigProperty();
        kbJwtMaxAge.setName(CFG_KBJWT_MAX_AGE_SEC);
        kbJwtMaxAge.setLabel("KB-JWT max age (secunde)");
        kbJwtMaxAge.setType(ProviderConfigProperty.STRING_TYPE);
        kbJwtMaxAge.setHelpText("Vârsta maximă a KB-JWT (secunde). Valori mai mari permit răspunsuri lente din wallet.");
        kbJwtMaxAge.setDefaultValue(String.valueOf(DEFAULT_KBJWT_MAX_AGE_SEC));

        return List.of(clientId, pidVct, diplomaVct, stateTimeout, kbJwtMaxAge);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {}

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getReferenceCategory() { return "passwordless"; }

    @Override
    public boolean isUserSetupAllowed() { return false; }
}