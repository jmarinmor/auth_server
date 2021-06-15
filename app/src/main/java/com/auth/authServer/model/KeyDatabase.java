package com.auth.authServer.model;

import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;

import java.security.KeyPair;

public interface KeyDatabase extends AutoCloseable {

    ErrorCode executeAdminCommand(String commandToDecrypt);
    AdminCommand decryptAdminCommand(String commandToDecrypt);

    void panic();

    String getRandomPublicKeyName();
    KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value);
    NamedPublicKey getServerPublicKey(String name);

    String encrypt(Object objectToEncrypt, String keyName);
    <T> T decrypt(String objectToDecrypt, Class<T> aClass, String keyName);
}
