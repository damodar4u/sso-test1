package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.*;
import java.io.IOException;
import java.net.URI;
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
        String redirectUri = "http://localhost:8080/sso-project/auth/redirect";

        // Log key parameters
        logger.info("Tenant ID: {}", tenantId);
        logger.info("Client ID: {}", clientId);
        logger.info("Redirect URI: {}", redirectUri);

        if (authCode != null) {
            try {
                // Log received auth code
                logger.info("Authorization Code: {}", authCode);

                // Create Confidential Client Application
                ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                        clientId,
                        ClientCredentialFactory.createFromSecret("wrj8Q~GDDSdyrx1jWLj7DaMISypNvoMIP6cpLbSL"))
                        .authority("https://login.microsoftonline.com/" + tenantId)
                        .build();

                // Set up authorization parameters
                AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                        authCode, new URI(redirectUri))
                        .scopes(Collections.singleton("openid profile email"))
                        .build();

                // Acquire token and user details
                IAuthenticationResult result = app.acquireToken(parameters).join();

                // Log token details
                logger.info("Access Token: {}", result.accessToken());
                logger.info("Account Username: {}", result.account().username());

                // **Print all claims from the ID token**
                printAllClaims(result.idToken());

                // Extract and assign user roles
                String userRole = getUserRoleFromToken(result.idToken());
                request.getSession().setAttribute("user", result.account());
                request.getSession().setAttribute("userRole", userRole);

                // Log assigned role
                logger.info("Assigned Role: {}", userRole);

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
     * Extract roles from the ID token.
     */
    private String getUserRoleFromToken(String idToken) {
        try {
            // Parse the ID token
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);

            // Extract claims
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Extract roles
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
            logger.error("Error parsing ID token and extracting roles", e);
        }

        // Default role if no roles are found
        return "RegularUser";
    }

    /**
     * Print all claims from the ID token for debugging purposes.
     */
    private void printAllClaims(String idToken) {
        try {
            // Parse the ID token using Nimbus JWT library
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);

            // Extract claims from the token
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Log all claims
            logger.info("All Claims in the ID Token:");
            for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
                logger.info("{}: {}", entry.getKey(), entry.getValue());
            }
        } catch (Exception e) {
            logger.error("Error parsing ID token and printing claims", e);
        }
    }
}
