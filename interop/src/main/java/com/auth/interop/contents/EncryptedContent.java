package com.auth.interop.contents;

import com.google.gson.Gson;

import javax.crypto.Cipher;
import java.lang.reflect.ParameterizedType;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptedContent<T> {

    private static Class<?> mPersistentClass;
    // Base64
    public String content;

    public EncryptedContent() {
        if (mPersistentClass == null) {
            mPersistentClass = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        }
    }

    public EncryptedContent<T> setContent(T content, Cipher cipher, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        byte[] encryptedBytes = cipher.doFinal(json.getBytes());
        String encryptedBytesInBase64String = Base64.getEncoder().encodeToString(encryptedBytes);
        this.content = encryptedBytesInBase64String;
        return this;
    }

    public T getContent(Cipher cipher, Gson serializer) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(content);
        String json = new String(cipher.doFinal(encryptedBytes));
        T obj = serializer.fromJson(json, (Class<T>)mPersistentClass);
        return obj;
    }

    public EncryptedContent<T> setContent(T content, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        String jsonBase64String = Base64.getEncoder().encodeToString(json.getBytes());
        //String sbinary = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        this.content = jsonBase64String;
        return this;
    }

    public T getContent(Gson serializer) throws Exception {
        byte[] jsonBase64Bytes = Base64.getDecoder().decode(content);
        String json = new String(jsonBase64Bytes);
        T c = serializer.fromJson(json, (Class<T>)mPersistentClass);
        return c;
    }


}
