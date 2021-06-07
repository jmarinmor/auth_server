package com.auth.authServer.model;

import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.google.gson.Gson;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private final static AuthDatabase mDatabase = new AuthDatabaseImplementationRAM();
    private final static Gson mGson = new Gson();

    public static AuthDatabase getDatabase() {
        return mDatabase;
    }

    public static Gson getGson() {
        return mGson;
    }
}
