package com.auth.authServer.model;

import com.auth.authServer.PrivateDatabase;
import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.google.gson.Gson;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private final static PrivateDatabase mDatabase = null;
    private final static Gson mGson = new Gson();

    public static PrivateDatabase getDatabase() {
        return mDatabase;
    }

    public static Gson getGson() {
        return mGson;
    }
}
