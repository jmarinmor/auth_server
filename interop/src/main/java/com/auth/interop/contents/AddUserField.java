package com.auth.interop.contents;

import com.google.gson.Gson;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.util.Base64;

public class AddUserField {
    public String fieldName;

    public AddUserField(String fieldName) {
        this.fieldName = fieldName;
    }
}
