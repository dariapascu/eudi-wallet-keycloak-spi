package com.license.eudi.openid4vp;

import org.jboss.logging.Logger;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


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
    

    public RequestObject getRequestObject(String requestId) {
        // Single-use: consumat la primul fetch 
        RequestObject req = requests.remove(requestId);
        if (req == null) {
            LOG.warnf("Request object not found or already consumed: %s", requestId);
            return null;
        }

        if (System.currentTimeMillis() - req.createdAt > EXPIRY_MS) {
            LOG.warnf("Request object expired: %s", requestId);
            return null;
        }

        LOG.infof("Request object consumed (single-use): id=%s, state=%s", requestId, req.state);
        return req;
    }
    
 
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
