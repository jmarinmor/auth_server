package com.auth.interop.contents;

import com.google.gson.Gson;

import java.util.Base64;
import java.util.Date;

public class GenerateAdminKeys {
    public static class Content {
        public Date date;
    }

    // Base64
    public String content;

    public GenerateAdminKeys setContent(Content content, Gson gson) {
        String s = gson.toJson(content);
        this.content = Base64.getEncoder().encodeToString(s.getBytes());
        return this;
    }
}
