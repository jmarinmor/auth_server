package com.auth.authServer.model;

import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.GenerateKeyPair;
import com.auth.interop.contents.SetAdminPrivateKey;
import com.auth.interop.contents.SetPanicPublicKey;

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
    ErrorCode setPanicPublicKey(EncryptedContent<SetPanicPublicKey> value);
    EncryptedContent<SetPanicPublicKey> getPanicPublicKey();

    // Admin private key is used for decipher incomming messages in order to check they are valid
    ErrorCode setAdminPrivateKey(EncryptedContent<SetAdminPrivateKey> value);

    KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value);
    NamedPublicKey getServerPublicKey(String name);
}
