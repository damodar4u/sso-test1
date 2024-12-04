package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.*;

public class AuthCallbackServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(AuthCallbackServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authCode = request.getParameter("code");
        String tenantId = "xxxxxxxxxxxxxxxxx";
        String clientId = "xxxxxxxxxxxxxxx";
        String clientSecret = "xxxxxxxxxxxxxxxx";
        String redirectUri = "http://localhost:8080/sso-project/auth/redirect";

        if (authCode != null) {
            try {
                logger.info("Authorization Code: {}", authCode);

                // Create Confidential Client Application
                ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                        clientId,
                        ClientCredentialFactory.createFromSecret(clientSecret))
                        .authority("https://login.microsoftonline.com/" + tenantId)
                        .build();

                // Set up authorization parameters
                AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                        authCode, new URI(redirectUri))
                        .scopes(Collections.singleton("openid profile email Directory.Read.All"))
                        .build();

                // Acquire token and user details
                IAuthenticationResult result = app.acquireToken(parameters).join();

                // Log token details
                String accessToken = result.accessToken();
                String idToken = result.idToken();

                logger.info("Access Token: {}", accessToken);
                logger.info("ID Token: {}", idToken);

                // Parse ID token and print roles, groups, and claim sources
                parseAndPrintRolesGroupsAndClaims(idToken, accessToken);

                // Redirect to the home page after login
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
     * Parse ID token and print roles, groups, and handle claim sources.
     */
    private void parseAndPrintRolesGroupsAndClaims(String idToken, String accessToken) {
        try {
            // Parse the ID token
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Print all claims for debugging
            logger.info("All Claims in the ID Token:");
            for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
                logger.info("{}: {}", entry.getKey(), entry.getValue());
            }

            // Check and print roles
            if (claims.getClaim("roles") != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.getClaim("roles");
                logger.info("Roles in the ID Token: {}", roles);
            }

            // Check and print groups or claim sources
            if (claims.getClaim("_claim_names") != null && claims.getClaim("_claim_sources") != null) {
                logger.info("Claim Names: {}", claims.getClaim("_claim_names"));
                logger.info("Claim Sources: {}", claims.getClaim("_claim_sources"));

                // Fetch group details using Microsoft Graph API
                List<String> groupIds = fetchGroupsFromTransitiveMemberOf(accessToken);
                logger.info("Group IDs from transitiveMemberOf: {}", groupIds);
            }
        } catch (Exception e) {
            logger.error("Error parsing ID token and retrieving roles/groups", e);
        }
    }

    /**
     * Fetch group details from Microsoft Graph API using transitiveMemberOf.
     */
    private List<String> fetchGroupsFromTransitiveMemberOf(String accessToken) {
        List<String> groupNames = new ArrayList<>();
        try {
            URL url = new URL("https://graph.microsoft.com/v1.0/me/transitiveMemberOf");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Content-Type", "application/json");

            // Process the response
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                // Parse group display names and IDs from the response
                JSONObject jsonResponse = new JSONObject(response.toString());
                JSONArray values = jsonResponse.getJSONArray("value");
                for (int i = 0; i < values.length(); i++) {
                    JSONObject group = values.getJSONObject(i);
                    String groupName = group.optString("displayName", "Unknown");
                    String groupId = group.optString("id", "Unknown");
                    logger.info("Group Name: {}, Group ID: {}", groupName, groupId);
                    groupNames.add(groupName);
                }
            } else {
                logger.error("Failed to fetch group details. HTTP Response Code: {}", responseCode);
            }
        } catch (Exception e) {
            logger.error("Error fetching group details from Microsoft Graph API", e);
        }
        return groupNames;
    }
}
