package com.auth.authServer.model;

import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;
import com.auth.interop.requests.CommandRequest;

import java.security.KeyPair;

public interface KeyDatabase extends AutoCloseable {

    ErrorCode executeAdminCommand(CommandRequest<AdminCommand> command);
    AdminCommand decryptAdminCommand(CommandRequest<AdminCommand> command);

    void panic();

    String getRandomPublicKeyName();
    KeyPair generateKeyPair();
    NamedPublicKey getServerPublicKey(String name);

    String encrypt(Object objectToEncrypt, String keyName);
    <T> T decrypt(String objectToDecrypt, Class<T> aClass, String keyName);
}
