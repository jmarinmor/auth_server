package com.auth.interop;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class User {
    String NAME_FIELD = "name";
    String VOID_STRING = "";

    public UUID id;
    public Map<String, String> values;

    // Application data
    public Set<String> appFields;
    public String appCode;
    public byte[] appPublicKey;

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

}
