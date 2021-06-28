package com.auth.authServer.model;

import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.servers.key.model.KeyDatabase;
import com.servers.key.model.KeyServer;
import com.servers.key.model.implementations.KeyDatabaseImplementationRAM;
import com.google.gson.Gson;
import com.jcore.database.sql.ConnectionPool;

public class Application {
    public static final boolean DEBUG_MODE = true;

    private static ConnectionPool<AuthDatabase> mAuthDatabase = null;
    private static KeyServer mKeyServer = null;
    private final static Gson mGson = new Gson();

    static {
        mKeyServer = new KeyServer(new KeyDatabaseImplementationRAM());
        mAuthDatabase = new ConnectionPool<>(2, (String key, boolean isFirst) -> {
            return new AuthDatabaseImplementationRAM(mKeyServer.getDatabase());
        });
    }

    public static AuthDatabase getAuthDatabase() throws Exception {
        return mAuthDatabase.get("").value();
    }
    public static KeyDatabase getKeyDatabase() throws Exception {
        return mKeyServer.getDatabase();
    }

    public static Gson getGson() {
        return mGson;
    }
}
