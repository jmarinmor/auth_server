package com.auth.authServer.model;

import com.google.gson.Gson;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private final static AuthDatabase mAuthDatabase = null;
    private final static KeyDatabase mKeyDatabase = null;
    private final static Gson mGson = new Gson();

    public static AuthDatabase getAuthDatabase() {
        return mAuthDatabase;
    }
    public static KeyDatabase getKeyDatabase() {
        return mKeyDatabase;
    }

    public static Gson getGson() {
        return mGson;
    }
}
