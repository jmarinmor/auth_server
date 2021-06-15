package com.auth.interop.contents;

import com.google.gson.Gson;
import com.jcore.crypto.Crypter;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ContentEncrypter {

    public static String encryptContent(Object content, Crypter cipher1, Crypter cipher2, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        byte[] encryptedBytes1 = cipher1.crypt(json.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedBytes2 = cipher2.crypt(encryptedBytes1);
        String encryptedBytesInBase64String = Base64.getEncoder().encodeToString(encryptedBytes2);
        return encryptedBytesInBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Crypter cipher1, Crypter cipher2, Gson serializer) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedContent);
        byte[] bytes1 = cipher1.crypt(encryptedBytes);
        String json = new String(cipher2.crypt(bytes1), StandardCharsets.UTF_8);
        T obj = serializer.fromJson(json, aClass);
        return obj;
    }

    public static String encryptContent(Object content, Crypter cipher, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        byte[] src = json.getBytes(StandardCharsets.UTF_8);
        //byte[] encryptedBytes = cipher.doFinal(src);
        byte[] encryptedBytes = cipher.crypt(src);
        String encryptedBytesInBase64String = Base64.getEncoder().encodeToString(encryptedBytes);
        return encryptedBytesInBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Crypter cipher, Gson serializer) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedContent);
        byte[] decryptedBytes = cipher.crypt(encryptedBytes);
        String json = new String(decryptedBytes, StandardCharsets.UTF_8);
        T obj = serializer.fromJson(json, aClass);
        return obj;
    }

    public static String encryptContent(Object content, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        String jsonBase64String = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        //String sbinary = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        return jsonBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Gson serializer) throws Exception {
        byte[] jsonBase64Bytes = Base64.getDecoder().decode(encryptedContent);
        String json = new String(jsonBase64Bytes, StandardCharsets.UTF_8);
        T c = serializer.fromJson(json, aClass);
        return c;
    }
}
