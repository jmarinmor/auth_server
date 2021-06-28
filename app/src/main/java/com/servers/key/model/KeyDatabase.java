package com.servers.key.model;

import com.servers.interop.ErrorCode;
import com.servers.interop.NamedPublicKey;
import com.servers.interop.commands.GetRandomPublicKeyName;
import com.google.gson.Gson;
import com.jcore.crypto.CipherUtils;
import com.jcore.crypto.Crypter;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public interface KeyDatabase extends AutoCloseable {

    byte[] getAdminPublicKey();
    ErrorCode setAdminPublicKey(byte[] key);
    byte[] getServicePublicKey();
    byte[] getServicePrivateKey();
    ErrorCode setServiceKeyPair(byte[] publicKey, byte[] privateKey);

    void panic();

    String getRandomPublicKeyName(GetRandomPublicKeyName.Encoding encoding);
    NamedPublicKey getServerPublicKey(String name);

    byte[] encrypt(byte[] stringToEncrypt, String keyName);
    byte[] decrypt(byte[] objectToDecrypt, String keyName);

    default KeyPair generateKeyPair() {
        try {
            KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
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
