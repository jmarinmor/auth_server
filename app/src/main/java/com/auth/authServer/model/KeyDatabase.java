package com.auth.authServer.model;

import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.GenerateKeyPair;
import com.auth.interop.contents.AdminPrivateKey;
import com.auth.interop.contents.PanicPublicKey;

import java.security.KeyPair;

public interface KeyDatabase extends AutoCloseable {
    // ** Panic key is used to cipher data in case of panic
    /**
     * This functions sets the panic public key. In the case of panic, all the internal kays will
     * be ciphered by this public key, so the only way to decipher it again is to call the setAlive
     * function giving the private key to restore them.
     * @param value
     * @return
     */
    ErrorCode setPanicPublicKey(EncryptedContent<PanicPublicKey> value);
    EncryptedContent<PanicPublicKey> getPanicPublicKey();

    // Admin private key is used for decipher incomming messages in order to check they are valid
    ErrorCode setAdminPrivateKey(EncryptedContent<AdminPrivateKey> value);

    String getRandomPublicKeyName();
    KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value);
    NamedPublicKey getServerPublicKey(String name);

    String encrypt(Object objectToEncrypt, String keyName);
    <T> T decrypt(String objectToDecrypt, Class<T> aClass, String keyName);
}
