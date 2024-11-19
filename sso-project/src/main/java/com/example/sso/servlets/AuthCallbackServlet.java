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

                // Process roles and groups from the token
                processRolesAndGroups(result.idToken());

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
     * Process roles and groups from the token.
     */
    private void processRolesAndGroups(String idToken) {
        try {
            JWT jwt = com.nimbusds.jwt.JWTParser.parse(idToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Extract roles from the token
            if (claims.getClaim("roles") != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.getClaim("roles");
                logger.info("Roles (includes groups emitted as roles): {}", roles);
            } else {
                logger.info("No roles found in the token.");
            }
        } catch (Exception e) {
            logger.error("Error processing roles/groups from token", e);
        }
    }
}
