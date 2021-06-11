package com.auth.interop.contents;

import com.google.gson.Gson;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.util.Base64;

public class AddUserField {
    public static class Content {
        public String fieldName;

        public Content(String fieldName) {
            this.fieldName = fieldName;
        }
    }

    // Base64
    public String content;

    public AddUserField setContent(Content content, Cipher cipher, Gson serializer) throws Exception {
        String data = serializer.toJson(content);
        byte[] binary = cipher.doFinal(data.getBytes());
        String sbinary = Base64.getEncoder().encodeToString(binary);
        this.content = sbinary;
        return this;
    }

    public Content getContent(Cipher cipher, Gson serializer) throws Exception {
        byte[] data = Base64.getDecoder().decode(content);
        String s = new String(cipher.doFinal(data));
        Content c = serializer.fromJson(s, Content.class);
        return c;
    }



}
