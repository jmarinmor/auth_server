package com.servers.interop.contents;

import java.util.Set;

public class AlterUserField {
    public String name;
    public Set<String> properties;
    public boolean overrideExisting;
    public boolean removeField;

    public AlterUserField() {
    }

    public AlterUserField(Set<String> properties) {
        this.properties = properties;
    }
}
