package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.GenerateKeyPair;
import com.auth.interop.contents.SetAdminPrivateKey;
import com.auth.interop.contents.SetPanicPublicKey;

import java.security.KeyPair;

public class KeyDatabaseImplementationRAM implements KeyDatabase {

    @Override
    public ErrorCode setPanicPublicKey(EncryptedContent<SetPanicPublicKey> value) {
        return null;
    }

    @Override
    public EncryptedContent<SetPanicPublicKey> getPanicPublicKey() {
        return null;
    }

    @Override
    public ErrorCode setAdminPrivateKey(EncryptedContent<SetAdminPrivateKey> value) {
        return null;
    }

    @Override
    public KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value) {
        return null;
    }

    @Override
    public NamedPublicKey getServerPublicKey(String name) {
        return null;
    }

    @Override
    public void close() throws Exception {

    }
}
