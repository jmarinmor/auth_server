package com.servers.key.model.implementations;

import com.servers.interop.ErrorCode;
import com.servers.interop.NamedPublicKey;
import com.servers.interop.commands.GetRandomPublicKeyName;
import com.jcore.crypto.CipherUtils;
import com.jcore.crypto.Crypter;
import com.servers.key.model.KeyDatabase;
import org.apache.commons.codec.digest.DigestUtils;

import java.security.KeyPair;
import java.util.*;

public class KeyDatabaseImplementationRAM implements KeyDatabase {

    public final int MAX_KEY_COUNT = 2;

    private byte[] mAdminPublicKey;
    private byte[] mServicePublicKey;
    private byte[] mServicePrivateKey;
    private Random mRandom = new Random();

    private Map<String, byte[]> mPublicKey = new HashMap();
    private Map<String, byte[]> mPrivateKey = new HashMap();
    private Map<String, byte[]> mEncryptedPrivateKey = new HashMap();
    private boolean mInPanic;

    @Override
    public void panic() {
        mInPanic = true;
        if (mAdminPublicKey != null) {
            synchronized (mPrivateKey) {
                synchronized (mEncryptedPrivateKey) {
                    try {
                        Crypter.Encrypter encrypter = Crypter.Encrypter.newFromRSAPublicKey(mAdminPublicKey);

                        for (Map.Entry<String, byte[]> entry : mPrivateKey.entrySet()) {
                            String sha256hex = DigestUtils.sha256Hex(entry.getKey());
                            byte[] encrypted = encrypter.crypt(entry.getValue());
                            mEncryptedPrivateKey.put(sha256hex, encrypted);
                        }
                        mPrivateKey.clear();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    @Override
    public String getRandomPublicKeyName(GetRandomPublicKeyName.Encoding encoding) {
        synchronized (mEncryptedPrivateKey) {
            if (mInPanic || mEncryptedPrivateKey.size() > 0)
                return null;
        }

        synchronized (mPublicKey) {
            Set<String> set = mPublicKey.keySet();
            ArrayList<String> list = new ArrayList<>(set);
            String name;
            int key_index = -1;
            if (list.size() < MAX_KEY_COUNT) {
                try {
                    UUID uuid = UUID.randomUUID();
                    KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
                    name = uuid.toString();
                    String private_name = DigestUtils.sha256Hex(name.toString());

                    byte[] public_key = pair.getPublic().getEncoded();
                    byte[] private_key = pair.getPrivate().getEncoded();
                    mPublicKey.put(name, public_key);
                    synchronized (mPrivateKey) {
                        mPrivateKey.put(private_name, private_key);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                }
            } else {
                key_index = mRandom.nextInt() % MAX_KEY_COUNT;
                name = list.get(key_index);
            }
            return name;
        }
    }

    @Override
    public NamedPublicKey getServerPublicKey(String name) {
        byte[] key = getPublicKeyBytes(name);
        if (key != null) {
            NamedPublicKey ret = new NamedPublicKey();
            ret.key = CipherUtils.encodeBytesToBase64String(key);
            return ret;
        }
        return null;
    }

    public byte[] getPublicKeyBytes(String keyName) {
        synchronized (mPublicKey) {
            byte[] key = mPublicKey.get(keyName);
            if (key == null) {
                //return ContentEncrypter.encryptContent(objectToEncrypt, mGson);
                return null;
            } else {
                return key;
            }
        }
    }

    @Override
    public byte[] encrypt(byte[] toEncrypt, String keyName) {
        byte[] bytes = getPublicKeyBytes(keyName);
        if (bytes != null) {
            try {
                Crypter.Encrypter encrypter = Crypter.Encrypter.newFromRSAPublicKey(bytes);
                byte[] ret = encrypter.crypt(toEncrypt);
                return ret;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public byte[] getPrivateKeyBytes(String keyName) {
        synchronized (mPrivateKey) {
            String private_name = DigestUtils.sha256Hex(keyName);
            byte[] key = mPrivateKey.get(private_name);
            if (key == null) {
                return null;
                //return ContentEncrypter.decryptContent(aClass, objectToDecrypt, mGson);
            } else {
                return key;
            }
        }
    }

    @Override
    public byte[] decrypt(byte[] toDecrypt, String keyName) {
        byte[] bytes = getPrivateKeyBytes(keyName);
        if (bytes != null) {
            try {
                Crypter.Decrypter decrypter = Crypter.Decrypter.newFromRSAPrivateKey(bytes);
                byte[] ret = decrypter.crypt(toDecrypt);
                return ret;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public void close() throws Exception {

    }

    @Override
    public byte[] getAdminPublicKey() {
        return mAdminPublicKey;
    }

    @Override
    public ErrorCode setAdminPublicKey(byte[] key) {
        if (key == null)
            return ErrorCode.INVALID_PARAMS;
        try {
            Crypter.Decrypter.newFromRSAPublicKey(key);
            mAdminPublicKey = key;
            return ErrorCode.SUCCEDED;
        } catch (Exception e) {
            e.printStackTrace();
            return ErrorCode.INVALID_PARAMS;
        }
    }

    @Override
    public byte[] getServicePublicKey() {
        return mServicePublicKey;
    }

    @Override
    public byte[] getServicePrivateKey() {
        return mServicePrivateKey;
    }

    @Override
    public ErrorCode setServiceKeyPair(byte[] publicKey, byte[] privateKey) {
        if (publicKey == null || privateKey == null)
            return ErrorCode.INVALID_PARAMS;
        try {
            Crypter.Decrypter.newFromRSAPublicKey(publicKey);
            Crypter.Decrypter.newFromRSAPrivateKey(privateKey);
            mServicePublicKey = publicKey;
            mServicePrivateKey = privateKey;
            return ErrorCode.SUCCEDED;
        } catch (Exception e) {
            e.printStackTrace();
            return ErrorCode.INVALID_PARAMS;
        }
    }


}
