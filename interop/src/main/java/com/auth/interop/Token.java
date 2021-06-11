package com.auth.interop;

import com.auth.interop.contents.EncryptedContent;

import java.util.Date;
import java.util.Map;

public class Token {
    public static class UserData {
        public String applicationCode;
        public String applicationName;
        public Map<String, String> values;
        public Date date;
    }

    public String serverPublicKeyName;
    public EncryptedContent<UserData> userData;
}
