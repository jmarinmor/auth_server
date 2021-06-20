package com.auth.interop;

import java.util.HashMap;
import java.util.Map;

public class UserFields {
    public enum FieldType {
        STRING_TYPE,
        INTEGER_TYPE
    }
    public static class FieldProperties {
        public FieldType type;

        public boolean checkValue(String value) {
            return true;
        }

        public boolean isValid() {
            return true;
        }

        public FieldProperties(FieldType type) {
            this.type = type;
        }
    }
    public Map<String, FieldProperties> fields = new HashMap<>();

}
