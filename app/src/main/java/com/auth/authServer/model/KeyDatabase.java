package com.auth.authServer.model;

import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;
import com.auth.interop.requests.CommandRequest;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public interface KeyDatabase extends AutoCloseable {
    enum Encoding {
        ASYMMETRIC,
        SYMMETRIC
    }

    ErrorCode executeAdminCommand(CommandRequest<AdminCommand> command);
    AdminCommand decryptAdminCommand(CommandRequest<AdminCommand> command);

    void panic();

    String getRandomPublicKeyName(Encoding encoding);
    KeyPair generateKeyPair();
    NamedPublicKey getServerPublicKey(String name);

    byte[] encrypt(byte[] stringToEncrypt, String keyName);
    byte[] decrypt(byte[] objectToDecrypt, String keyName);

    default String encryptObjectToBase64(Object objectToEncrypt, String keyName, Gson serializer) {
        if (objectToEncrypt == null || keyName == null || serializer == null)
            return null;
        String str = serializer.toJson(objectToEncrypt);
        byte[] bytes = encrypt(str.getBytes(StandardCharsets.UTF_8), keyName);
        return Crypter.bytesToBase64String(bytes);
    }

    default <T> T decryptBase64ToObject(String objectToDecrypt, Class<T> aClass, String keyName, Gson serializer) {
        if (objectToDecrypt == null || aClass == null || keyName == null || serializer == null)
            return null;
        byte[] bytes = Crypter.base64StringToBytes(objectToDecrypt);
        byte[] decrypted = decrypt(bytes, keyName);
        String s = new String(decrypted, StandardCharsets.UTF_8);
        return serializer.fromJson(s, aClass);
    }
}
