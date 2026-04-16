package com.license.eudi.session;

import org.jboss.logging.Logger;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Manager pentru legarea state-ului din Authorization Request cu sesiunea Keycloak.
 * Folosit pentru a conecta QR code-ul scanat pe telefon cu sesiunea din browser.
 */
public class SessionStateManager {
    
    private static final Logger LOG = Logger.getLogger(SessionStateManager.class);
    
    private static final SessionStateManager INSTANCE = new SessionStateManager();
    
    private final Map<String, SessionData> stateMap = new ConcurrentHashMap<>();
    
    private final Map<String, String> sessionToStateMap = new ConcurrentHashMap<>();
    
    private static final long DEFAULT_STATE_TIMEOUT_MS = TimeUnit.MINUTES.toMillis(10);
    
    private SessionStateManager() {
        startCleanupThread();
    }
    
    public static SessionStateManager getInstance() {
        return INSTANCE;
    }
    
    /**
     * Genereaza un state nou si il asociaza cu sesiunea Keycloak
     */
    public String createState(String authSessionId, String nonce, String responseUri, String clientId,
                               String expectedVct, long stateTimeoutMs, long kbJwtMaxAgeMs) {
        String state = UUID.randomUUID().toString();

        long timeout = stateTimeoutMs > 0 ? stateTimeoutMs : DEFAULT_STATE_TIMEOUT_MS;
        SessionData data = new SessionData(authSessionId, nonce, responseUri, clientId, expectedVct,
                timeout, kbJwtMaxAgeMs, System.currentTimeMillis());
        stateMap.put(state, data);
        sessionToStateMap.put(authSessionId, state);
        
        LOG.infof("Created state mapping: state=%s, authSessionId=%s, nonce=%s", state, authSessionId, nonce);
        
        return state;
    }
    
    /**
     * Obtine datele sesiunii pentru un state dat
     */
    public SessionData getSessionData(String state) {
        SessionData data = stateMap.get(state);
        
        if (data == null) {
            LOG.warnf("No session data found for state: %s", state);
            return null;
        }
        
        if (System.currentTimeMillis() - data.getCreatedAt() > data.getTimeoutMs()) {
            LOG.warnf("State expired: %s", state);
            removeState(state);
            return null;
        }
        
        return data;
    }
    
    /**
     * Inregistreaza momentul in care VP token-ul a fost primit de la wallet (POST /callback)
     */
    public void setVpReceivedAt(String state, long epochMs) {
        SessionData data = stateMap.get(state);
        if (data != null) {
            data.setVpReceivedAt(epochMs);
        }
    }

    /**
     * Marcheaza un state ca fiind autentificat cu succes
     */
    public void markAuthenticated(String state, Map<String, Object> claims, long validatedAt) {
        SessionData data = stateMap.get(state);
        if (data != null) {
            data.setAuthenticated(true);
            data.setClaims(claims);
            data.setValidatedAt(validatedAt);
            LOG.infof("Marked state as authenticated: %s", state);
        }
    }
    
    /**
     * Verifica daca un state a fost autentificat
     */
    public boolean isAuthenticated(String state) {
        SessionData data = stateMap.get(state);
        return data != null && data.isAuthenticated();
    }
    
    /**
     * Obtine claim-urile pentru un state autentificat
     */
    public Map<String, Object> getClaims(String state) {
        SessionData data = stateMap.get(state);
        return data != null ? data.getClaims() : null;
    }
    
    /**
     * Sterge un state din cache
     */
    public void removeState(String state) {
        SessionData data = stateMap.remove(state);
        if (data != null) {
            sessionToStateMap.remove(data.getAuthSessionId());
            LOG.infof("Removed state: %s", state);
        }
    }
    
    /**
     * Obtine state-ul pentru o sesiune Keycloak
     */
    public String getStateByAuthSession(String authSessionId) {
        return sessionToStateMap.get(authSessionId);
    }
    
    /**
     * Thread pentru curatarea state-urilor expirate
     */
    private void startCleanupThread() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(30));
                    cleanupExpiredStates();
                } catch (InterruptedException e) {
                    LOG.warn("Cleanup thread interrupted", e);
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.setName("SessionStateManager-Cleanup");
        cleanupThread.start();
    }
    
    /**
     * Curata state-urile expirate
     */
    private void cleanupExpiredStates() {
        long now = System.currentTimeMillis();
        int removed = 0;
        
        for (Map.Entry<String, SessionData> entry : stateMap.entrySet()) {
            if (now - entry.getValue().getCreatedAt() > entry.getValue().getTimeoutMs()) {
                removeState(entry.getKey());
                removed++;
            }
        }
        
        if (removed > 0) {
            LOG.infof("Cleaned up %d expired states", removed);
        }
    }
    
    /**
     * Clasa pentru datele sesiunii
     */
    public static class SessionData {
        private final String authSessionId;
        private final String nonce;
        private final String responseUri;
        private final String clientId;
        private final String expectedVct;
        private final long timeoutMs;
        private final long kbJwtMaxAgeMs;
        private final long createdAt;
        private boolean authenticated;
        private Map<String, Object> claims;
        private long vpReceivedAt;   // when POST /callback arrived from wallet
        private long validatedAt;    // when crypto validation completed

        public SessionData(String authSessionId, String nonce, String responseUri, String clientId,
                           String expectedVct, long timeoutMs, long kbJwtMaxAgeMs, long createdAt) {
            this.authSessionId = authSessionId;
            this.nonce = nonce;
            this.responseUri = responseUri;
            this.clientId = clientId;
            this.expectedVct = expectedVct;
            this.timeoutMs = timeoutMs;
            this.kbJwtMaxAgeMs = kbJwtMaxAgeMs;
            this.createdAt = createdAt;
            this.authenticated = false;
        }

        public String getAuthSessionId() {
            return authSessionId;
        }

        public String getNonce() {
            return nonce;
        }

        public String getResponseUri() {
            return responseUri;
        }

        public String getClientId() {
            return clientId;
        }

        public String getExpectedVct() {
            return expectedVct;
        }

        public long getTimeoutMs() {
            return timeoutMs;
        }

        public long getKbJwtMaxAgeMs() {
            return kbJwtMaxAgeMs;
        }

        public long getCreatedAt() {
            return createdAt;
        }
        
        public boolean isAuthenticated() {
            return authenticated;
        }
        
        public void setAuthenticated(boolean authenticated) {
            this.authenticated = authenticated;
        }
        
        public Map<String, Object> getClaims() {
            return claims;
        }
        
        public void setClaims(Map<String, Object> claims) {
            this.claims = claims;
        }

        public long getVpReceivedAt() {
            return vpReceivedAt;
        }

        public void setVpReceivedAt(long vpReceivedAt) {
            this.vpReceivedAt = vpReceivedAt;
        }

        public long getValidatedAt() {
            return validatedAt;
        }

        public void setValidatedAt(long validatedAt) {
            this.validatedAt = validatedAt;
        }
    }
}
