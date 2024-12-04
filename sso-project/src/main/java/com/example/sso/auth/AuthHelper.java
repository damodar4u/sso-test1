package com.example.sso.auth;

import com.microsoft.aad.msal4j.*;

public class AuthHelper {
    private static ConfidentialClientApplication app;

    static {
        try {
            app = ConfidentialClientApplication.builder(
                "xxxxxxxxxxxxxx",
                ClientCredentialFactory.createFromSecret("xxxxxxxxxxxxxxx))
                .authority("https://login.microsoftonline.com/xxxxxxxxxx")
                .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ConfidentialClientApplication getApp() {
        return app;
    }
}
