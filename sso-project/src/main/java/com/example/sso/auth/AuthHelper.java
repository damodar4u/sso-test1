package com.example.sso.auth;

import com.microsoft.aad.msal4j.*;

public class AuthHelper {
    private static ConfidentialClientApplication app;

    static {
        try {
            app = ConfidentialClientApplication.builder(
                "78888168-35a9-4119-ba50-5fe8f05eefa4",
                ClientCredentialFactory.createFromSecret("wrj8Q~GDDSdyrx1jWLj7DaMISypNvoMIP6cpLbSL"))
                .authority("https://login.microsoftonline.com/b84a830a-a2a0-4dde-8caf-6f5dd8729519")
                .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ConfidentialClientApplication getApp() {
        return app;
    }
}
