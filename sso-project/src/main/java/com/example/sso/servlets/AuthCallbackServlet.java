package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.*;

public class AuthCallbackServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(AuthCallbackServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
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

                // Acquire token
                AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                        authCode, new URI(redirectUri))
                        .scopes(Collections.singleton("openid profile email Directory.Read.All"))
                        .build();
                IAuthenticationResult result = app.acquireToken(parameters).join();

                // Log token details
                String accessToken = result.accessToken();
                String idToken = result.idToken();
                logger.info("Access Token: {}", accessToken);
                logger.info("ID Token: {}", idToken);

                // Parse claims and handle groups and roles
                parseAndHandleClaims(idToken, accessToken);

                response.sendRedirect("/sso-project");
            } catch (Exception e) {
                logger.error("Error during authentication", e);
                try {
                    response.sendRedirect("/sso-project/error.jsp");
                } catch (IOException ioException) {
                    logger.error("Error redirecting after failure", ioException);
                }
            }
        } else {
            logger.error("Authorization code is missing");
            try {
                response.sendRedirect("/sso-project/error.jsp");
            } catch (IOException e) {
                logger.error("Error redirecting to error page", e);
            }
        }
    }

    private void parseAndHandleClaims(String idToken, String accessToken) {
        try {
            // Parse the ID token
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Log all claims
            logger.info("All Claims in the ID Token:");
            claims.getClaims().forEach((key, value) -> logger.info("{}: {}", key, value));

            // Print roles if available
            if (claims.getClaim("roles") != null) {
                List<String> roles = claims.getJSONArrayClaim("roles");
                logger.info("Roles: {}", roles);
            }

            // Check for claim sources and handle groups
            if (claims.getClaim("_claim_names") != null && claims.getClaim("_claim_sources") != null) {
                logger.info("Claim Names: {}", claims.getClaim("_claim_names"));
                logger.info("Claim Sources: {}", claims.getClaim("_claim_sources"));

                // Fetch and log groups using transitiveMemberOf
                fetchAndLogGroupsUsingTransitiveMemberOf(accessToken);
            }
        } catch (Exception e) {
            logger.error("Error parsing ID token and retrieving claims", e);
        }
    }

    private void fetchAndLogGroupsUsingTransitiveMemberOf(String accessToken) {
        try {
            URL url = new URL("https://graph.microsoft.com/v1.0/me/transitiveMemberOf");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Accept", "application/json");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                // Parse response and print group details
                logger.info("Groups from Microsoft Graph API (transitiveMemberOf):");
                parseGroupDetails(response.toString());
            } else {
                logger.error("Failed to fetch groups. HTTP Response Code: {}", responseCode);
            }
        } catch (Exception e) {
            logger.error("Error fetching groups using transitiveMemberOf", e);
        }
    }

    private void parseGroupDetails(String response) {
        JSONObject jsonResponse = new JSONObject(response);
        JSONArray groupsArray = jsonResponse.getJSONArray("value");
        for (int i = 0; i < groupsArray.length(); i++) {
            JSONObject group = groupsArray.getJSONObject(i);
            String id = group.getString("id");
            String displayName = group.optString("displayName", "No Display Name");
            logger.info("Group ID: {} | Display Name: {}", id, displayName);
        }
    }
}
