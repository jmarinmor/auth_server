package com.servers.interop;

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

    public static class PropertyEntry {
        public Long id;
        public boolean hidden;

        public PropertyEntry() {
        }

        public PropertyEntry(Long id) {
            this.id = id;
        }

        public PropertyEntry(Long id, boolean hidden) {
            this.id = id;
            this.hidden = hidden;
        }
    }

    public UUID id;
    public Type type;
    public Map<String, PropertyEntry> valueReferences;
}
