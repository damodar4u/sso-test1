package com.example.sso.servlets;

import com.microsoft.aad.msal4j.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.Collections;
import com.example.sso.auth.AuthHelper;

public class LoginServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ConfidentialClientApplication app = AuthHelper.getApp();
        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters.builder(
                "http://localhost:8080/sso-project/auth/redirect",
                Collections.singleton("openid profile email"))
            .responseMode(ResponseMode.QUERY)
            .build();
        response.sendRedirect(app.getAuthorizationRequestUrl(parameters).toString());
    }
}
