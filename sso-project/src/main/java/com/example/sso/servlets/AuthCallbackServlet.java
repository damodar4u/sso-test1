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

                logger.info("Access Token: {}", result.accessToken());
                logger.info("Account Username: {}", result.account().username());

                // Extract and log roles from token
                printRolesFromToken(result.idToken());

                // Fetch groups via Graph API
                List<String> groupIds = fetchGroupsFromGraphAPI(result.accessToken());
                logger.info("Groups from Graph API: {}", groupIds);

                // Assign user and role to session
                String userRole = getUserRoleFromToken(result.idToken());
                request.getSession().setAttribute("user", result.account());
                request.getSession().setAttribute("userRole", userRole);

                logger.info("Assigned Role: {}", userRole);

                // Redirect to the home page
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
     * Print roles from the ID token.
     */
    private void printRolesFromToken(String idToken) {
        try {
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            if (claims.getClaim("roles") != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.getClaim("roles");
                logger.info("Roles from token: {}", roles);
            } else {
                logger.info("No roles found in the token.");
            }
        } catch (Exception e) {
            logger.error("Error parsing roles from token", e);
        }
    }

    /**
     * Fetch groups for the user from Microsoft Graph API.
     */
    private List<String> fetchGroupsFromGraphAPI(String accessToken) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI("https://graph.microsoft.com/v1.0/me/transitiveMemberOf"))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("Graph API Response: {}", response.body());

            // Parse the response to extract group IDs (you may use a JSON parser like Jackson/Gson)
            return List.of(response.body()); // Replace this with proper JSON parsing
        } catch (Exception e) {
            logger.error("Error fetching groups from Graph API", e);
            return Collections.emptyList();
        }
    }

    /**
     * Extract user role from the ID token.
     */
    private String getUserRoleFromToken(String idToken) {
        try {
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            if (claims.getClaim("roles") != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.getClaim("roles");

                if (roles.contains("PrivilegedAdmin")) {
                    return "PrivilegedAdmin";
                } else if (roles.contains("RegularUser")) {
                    return "RegularUser";
                }
            }
        } catch (Exception e) {
            logger.error("Error parsing roles from token", e);
        }

        return "RegularUser";
    }
}
