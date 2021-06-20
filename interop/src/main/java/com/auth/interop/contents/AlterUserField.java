package com.auth.interop.contents;

import com.auth.interop.UserFields;

public class AlterUserField {
    public String name;
    public UserFields.FieldProperties properties;
    public boolean overrideExisting;
    public boolean removeField;

    public AlterUserField() {
    }

    public AlterUserField(String name, UserFields.FieldProperties properties) {
        this.name = name;
        this.properties = properties;
    }
}
