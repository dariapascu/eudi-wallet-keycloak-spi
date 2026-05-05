package com.license.eudi.openid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * REST endpoint for serving Request Objects in OpenID4VP.
 * Wallets fetch the actual presentation request from here.
 * 
 * Endpoint: GET /realms/{realm}/eudi-verifier/request/{requestId}
 */
public class RequestObjectResource implements RealmResourceProvider {
    
    private static final Logger LOG = Logger.getLogger(RequestObjectResource.class);
    private final KeycloakSession session;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public RequestObjectResource(KeycloakSession session) {
        this.session = session;
    }
    
    @Override
    public Object getResource() {
        return this;
    }
    
    @Override
    public void close() {
    }

    @GET
    @Path("/request/{requestId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequestObject(@PathParam("requestId") String requestId) {
        try {
            LOG.infof("Request object requested: %s", requestId);
            
            RequestObjectManager.RequestObject reqObj = 
                RequestObjectManager.getInstance().getRequestObject(requestId);
            
            if (reqObj == null) {
                LOG.warnf("Request object not found or expired: %s", requestId);
                return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "invalid_request", 
                                   "error_description", "Request object not found or expired"))
                    .build();
            }
            
            String presentationDefJson = new String(
                Base64.getUrlDecoder().decode(reqObj.presentationDefinition)
            );
            
            Map<String, Object> requestObject = new HashMap<>();
            requestObject.put("response_type", "vp_token");
            requestObject.put("response_mode", "direct_post");
            requestObject.put("client_id", reqObj.clientId);
            requestObject.put("response_uri", reqObj.responseUri);
            requestObject.put("nonce", reqObj.nonce);
            requestObject.put("state", reqObj.state);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> presentationDef = objectMapper.readValue(
                presentationDefJson, Map.class
            );
            requestObject.put("presentation_definition", presentationDef);
            
            LOG.infof("Serving request object %s: clientId=%s, responseUri=%s", 
                     requestId, reqObj.clientId, reqObj.responseUri);
            
            return Response.ok(requestObject).build();
            
        } catch (Exception e) {
            LOG.errorf(e, "Error serving request object %s", requestId);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(Map.of("error", "server_error", 
                               "error_description", "Failed to retrieve request object"))
                .build();
        }
    }
}
