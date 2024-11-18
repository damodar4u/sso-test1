package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AuthCallbackServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(AuthCallbackServlet.class);
    private static final String GRAPH_API_URL = "https://graph.microsoft.com/v1.0/groups/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authCode = request.getParameter("code");
        String tenantId = "b84a830a-a2a0-4dde-8caf-6f5dd8729519";
        String clientId = "78888168-35a9-4119-ba50-5fe8f05eefa4";
        String clientSecret = "wrj8Q~GDDSdyrx1jWLj7DaMISypNvoMIP6cpLbSL";
        String redirectUri = "http://localhost:8080/sso-project/auth/redirect";

        if (authCode != null) {
            try {
                // Exchange authorization code for tokens
                ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                        clientId,
                        ClientCredentialFactory.createFromSecret(clientSecret))
                        .authority("https://login.microsoftonline.com/" + tenantId)
                        .build();

                AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                        authCode, new URI(redirectUri))
                        .scopes(Collections.singleton("openid profile email Directory.Read.All"))
                        .build();

                IAuthenticationResult result = app.acquireToken(parameters).join();

                // Parse ID token and extract groups
                List<String> groupIds = extractGroupIdsFromToken(result.idToken());
                logger.info("Group IDs from token: {}", groupIds);

                // Fetch group names using Graph API and log them
                logger.info("Fetching group details for user...");
                for (String groupId : groupIds) {
                    String groupName = fetchGroupNameFromGraphAPI(groupId, result.accessToken());
                    logger.info("Group ID: {}, Group Name: {}", groupId, groupName);
                }
                logger.info("User belongs to the following groups:");
                groupIds.forEach(id -> logger.info("Group ID: {}", id));

                response.sendRedirect("/sso-project");
            } catch (Exception e) {
                logger.error("Error during authentication", e);
                response.sendRedirect("/sso-project/error.jsp");
            }
        } else {
            logger.error("Authorization code is missing");
            response.sendRedirect("/sso-project/error.jsp");
        }
    }

    /**
     * Extract group IDs from the ID token.
     */
    private List<String> extractGroupIdsFromToken(String idToken) throws Exception {
        JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        return (List<String>) claims.getClaim("groups");
    }

    /**
     * Fetch the group name from Microsoft Graph API.
     */
    private String fetchGroupNameFromGraphAPI(String groupId, String accessToken) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(GRAPH_API_URL + groupId))
                .header("Authorization", "Bearer " + accessToken)
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            // Parse response to extract display name
            Map<String, Object> groupDetails = new com.fasterxml.jackson.databind.ObjectMapper().readValue(response.body(), Map.class);
            return (String) groupDetails.get("displayName");
        } else {
            logger.error("Failed to fetch group name for ID {}: {}", groupId, response.body());
            return "Unknown Group";
        }
    }
}
