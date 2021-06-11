package com.auth.interop.utils;

import javax.crypto.Cipher;
import java.security.KeyPair;

public class CipherPair {
    private Cipher mEncrypter;
    private Cipher mDecrypter;

    public CipherPair(KeyPair keyPair, CipherUtils.Algorithm algorithm) {
        try {
            mEncrypter = CipherUtils.getEncrypter(algorithm, keyPair.getPrivate());
            mDecrypter = CipherUtils.getDecrypter(algorithm, keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Cipher getEncrypter() {
        return mEncrypter;
    }

    public Cipher getDecrypter() {
        return mDecrypter;
    }
}
