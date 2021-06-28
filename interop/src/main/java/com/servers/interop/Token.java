package com.servers.interop;

import java.util.Date;
import java.util.Map;

public class Token {
    public static class UserData {
        public String applicationCode;
        public String applicationName;
        public Map<String, Property> values;
        public Date date;
    }

    public String serverPublicKeyName;
    public String userData;
}
