package com.auth.interop.contents;

import com.google.gson.Gson;

import javax.crypto.Cipher;
import java.util.Base64;

public class ContentEncrypter {

    public static String encryptContent(Object content, Cipher cipher1, Cipher cipher2, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        byte[] encryptedBytes1 = cipher1.doFinal(json.getBytes());
        byte[] encryptedBytes2 = cipher2.doFinal(encryptedBytes1);
        String encryptedBytesInBase64String = Base64.getEncoder().encodeToString(encryptedBytes2);
        return encryptedBytesInBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Cipher cipher1, Cipher cipher2, Gson serializer) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedContent);
        byte[] bytes1 = cipher1.doFinal(encryptedBytes);
        String json = new String(cipher2.doFinal(bytes1));
        T obj = serializer.fromJson(json, aClass);
        return obj;
    }

    public static String encryptContent(Object content, Cipher cipher, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        byte[] encryptedBytes = cipher.doFinal(json.getBytes());
        String encryptedBytesInBase64String = Base64.getEncoder().encodeToString(encryptedBytes);
        return encryptedBytesInBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Cipher cipher, Gson serializer) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedContent);
        String json = new String(cipher.doFinal(encryptedBytes));
        T obj = serializer.fromJson(json, aClass);
        return obj;
    }

    public static String encryptContent(Object content, Gson serializer) throws Exception {
        String json = serializer.toJson(content);
        String jsonBase64String = Base64.getEncoder().encodeToString(json.getBytes());
        //String sbinary = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        return jsonBase64String;
    }

    public static <T> T decryptContent(Class<T> aClass, String encryptedContent, Gson serializer) throws Exception {
        byte[] jsonBase64Bytes = Base64.getDecoder().decode(encryptedContent);
        String json = new String(jsonBase64Bytes);
        T c = serializer.fromJson(json, aClass);
        return c;
    }
}
