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
    public Map<String, Property> values;
    public Map<String, Long> valueReferences;

    public Property getNameField() {
        return getUserField(NAME_FIELD);
    }

    public Property getUserField(String field) {
        if (field == null || values == null)
            return null;
        Property ret = values.get(field);
        if (ret == null)
            return null;
        return ret;
    }

    public User setName(String name) {
        if (values == null)
            values = new HashMap<>();
        values.put(NAME_FIELD, new Property(name));
        return this;
    }

}
