package com.auth.authServer.model;

import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private final static AuthDatabase mDatabase = new AuthDatabaseImplementationRAM();

    public static AuthDatabase getDatabase() {
        return mDatabase;
    }
}
