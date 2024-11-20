package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AuthCallbackServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(AuthCallbackServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authCode = request.getParameter("code");
        String tenantId = "b84a830a-a2a0-4dde-8caf-6f5dd8729519";
        String clientId = "78888168-35a9-4119-ba50-5fe8f05eefa4";
        String clientSecret = "wrj8Q~GDDSdyrx1jWLj7DaMISypNvoMIP6cpLbSL";
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
                fetchGroupsFromClaimSource(accessToken);
            }
        } catch (Exception e) {
            logger.error("Error parsing ID token and retrieving roles/groups", e);
        }
    }

    /**
     * Fetch group details from Microsoft Graph API using claim sources.
     */
    private void fetchGroupsFromClaimSource(String accessToken) {
        try {
            URL url = new URL("https://graph.microsoft.com/v1.0/me/getMemberObjects");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // Write the request body
            String requestBody = "{ \"securityEnabledOnly\": false }";
            connection.getOutputStream().write(requestBody.getBytes());

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

                logger.info("Group Details from Microsoft Graph API (getMemberObjects):");
                logger.info(response.toString());
            } else {
                logger.error("Failed to fetch group details. HTTP Response Code: {}", responseCode);
            }
        } catch (Exception e) {
            logger.error("Error fetching group details from Microsoft Graph API", e);
        }
    }
}
