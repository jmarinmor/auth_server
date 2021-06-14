package com.auth.interop;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class User {
    public static final String NAME_FIELD = "name";
    public static final String VOID_STRING = "";

    public enum Type {
        ADMIN,
        USER,
        APPLICATION
    }

    public UUID id;
    public Type type;
    public Map<String, String> values;
    public String publicKey;

    // Application data
    public Set<String> appFields;
    public String appCode;

    public String getNameField() {
        return getUserField(NAME_FIELD);
    }

    public String getUserField(String field) {
        if (field == null || values == null)
            return VOID_STRING;
        String ret = values.get(field);
        if (ret == null)
            return VOID_STRING;
        return ret;
    }

    public User setName(String name) {
        if (values == null)
            values = new HashMap<>();
        values.put(NAME_FIELD, name);
        return this;
    }
}
