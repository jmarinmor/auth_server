package com.auth.authServer.model;

import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.auth.authServer.model.implementations.KeyDatabaseImplementationRAM;
import com.google.gson.Gson;
import com.jcore.database.sql.ConnectionPool;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private static ConnectionPool<AuthDatabase> mAuthDatabase = null;
    private static ConnectionPool<KeyDatabase> mKeyDatabase = null;
    private final static Gson mGson = new Gson();

    static {
        mAuthDatabase = new ConnectionPool<>(2, (String key, boolean isFirst) -> {
            return new AuthDatabaseImplementationRAM();
        });

        mKeyDatabase = new ConnectionPool<>(2, (String key, boolean isFirst) -> {
            return new KeyDatabaseImplementationRAM();
        });
    }

    public static AuthDatabase getAuthDatabase() throws Exception {
        return mAuthDatabase.get("").value();
    }
    public static KeyDatabase getKeyDatabase() throws Exception {
        return mKeyDatabase.get("").value();
    }

    public static Gson getGson() {
        return mGson;
    }
}
