package com.auth.interop;

public class Property {
    public enum Type {
        STRING,
        URL
    }

    public Type type;
    public boolean detached;
    public String content;

    public Property(String content) {
        this.type = Type.STRING;
        this.content = content;
    }
}
