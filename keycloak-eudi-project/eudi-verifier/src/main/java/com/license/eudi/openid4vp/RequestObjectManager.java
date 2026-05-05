package com.license.eudi.openid4vp;

import org.jboss.logging.Logger;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages Request Objects for OpenID4VP "by reference" pattern.
 * Similar to credential_offer_uri in OpenID4VCI.
 * 
 * Pattern:
 * 1. QR Code contains: openid4vp://?request_uri=https://.../request/{id}
 * 2. Wallet fetches the actual request from that URI
 * 3. Request contains presentation_definition and response_uri
 */
public class RequestObjectManager {
    
    private static final Logger LOG = Logger.getLogger(RequestObjectManager.class);
    private static final RequestObjectManager INSTANCE = new RequestObjectManager();
    
    private final Map<String, RequestObject> requests = new ConcurrentHashMap<>();
    
    private final ScheduledExecutorService cleanupScheduler = 
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "RequestObjectManager-Cleanup");
            t.setDaemon(true);
            return t;
        });
    
    private static final long EXPIRY_MS = 5 * 60 * 1000;
    
    private RequestObjectManager() {
        cleanupScheduler.scheduleAtFixedRate(this::cleanupExpired, 1, 1, TimeUnit.MINUTES);
        LOG.info("RequestObjectManager initialized with 5-minute expiry");
    }
    
    public static RequestObjectManager getInstance() {
        return INSTANCE;
    }
    
    /**
     * Creates a new request object and returns its ID
     */
    public String createRequestObject(String clientId, String responseUri, 
                                      String nonce, String state, 
                                      String presentationDefinition) {
        String requestId = UUID.randomUUID().toString();
        
        RequestObject requestObject = new RequestObject(
            requestId,
            clientId,
            responseUri,
            nonce,
            state,
            presentationDefinition,
            System.currentTimeMillis()
        );
        
        requests.put(requestId, requestObject);
        LOG.infof("Created request object: id=%s, clientId=%s, responseUri=%s", 
                  requestId, clientId, responseUri);
        
        return requestId;
    }
    
    /**
     * Retrieves a request object by ID
     */
    public RequestObject getRequestObject(String requestId) {
        RequestObject req = requests.get(requestId);
        if (req == null) {
            LOG.warnf("Request object not found: %s", requestId);
            return null;
        }
        
        if (System.currentTimeMillis() - req.createdAt > EXPIRY_MS) {
            LOG.warnf("Request object expired: %s", requestId);
            requests.remove(requestId);
            return null;
        }
        
        return req;
    }
    
    /**
     * Removes expired request objects
     */
    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        int removed = 0;
        
        for (Map.Entry<String, RequestObject> entry : requests.entrySet()) {
            if (now - entry.getValue().createdAt > EXPIRY_MS) {
                requests.remove(entry.getKey());
                removed++;
            }
        }
        
        if (removed > 0) {
            LOG.infof("Cleaned up %d expired request objects", removed);
        }
    }
    
    /**
     * Immutable request object data
     */
    public static class RequestObject {
        public final String requestId;
        public final String clientId;
        public final String responseUri;
        public final String nonce;
        public final String state;
        public final String presentationDefinition;
        public final long createdAt;
        
        public RequestObject(String requestId, String clientId, String responseUri,
                           String nonce, String state, String presentationDefinition,
                           long createdAt) {
            this.requestId = requestId;
            this.clientId = clientId;
            this.responseUri = responseUri;
            this.nonce = nonce;
            this.state = state;
            this.presentationDefinition = presentationDefinition;
            this.createdAt = createdAt;
        }
    }
}
