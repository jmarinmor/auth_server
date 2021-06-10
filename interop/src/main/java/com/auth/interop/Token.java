package com.auth.interop;

import java.util.Date;
import java.util.Map;

public class Token {
    public static class User {
        public String applicationCode;
        public String applicationName;
        public Map<String, String> values;
        public Date date;
    }

    public String serverPublicKeyName;
    public byte[] userData;

    public User decypherUser(byte[] serverPublicKey) {
        return null;
    }
}
