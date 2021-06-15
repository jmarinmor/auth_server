package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;
import com.google.gson.Gson;
import com.jcore.utils.CipherUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.util.*;

public class KeyDatabaseImplementationRAM implements KeyDatabase {

    private static class KeyRecord {
        private String name;
        private String publicKeyBase64String;
        private KeyPair keys;
        private Cipher encrypter;
        private Cipher decrypter;
    }

    public final int MAX_KEY_COUNT = 2;

    private static byte[] mPanicPublicKey;
    private static byte[] mAdminPublicKey;
    private static Random mRandom = new Random();
    private static List<KeyRecord> mKeyList = new ArrayList<>();

    private static Gson mGson = new Gson();


    @Override
    public ErrorCode setPanicPublicKey(EncryptedContent<PanicPublicKey> value) {
        if (mPanicPublicKey == null) {
            PanicPublicKey content = null;
            try {
                content = value.getContent(mGson);
                byte[] key_bytes = CipherUtils.encodeBase64StringToBase64Bytes(content.key);
                if (key_bytes == null)
                    throw new Exception();
                CipherUtils.newPublicKeyFromBytes(key_bytes, CipherUtils.Algorithm.RSA);
                mPanicPublicKey = key_bytes;

            } catch (Exception e) {
                e.printStackTrace();
                return ErrorCode.INVALID_PARAMS;
            }
        } else {
            // TODO: 14/06/2021 Pensar esto
        }
        return ErrorCode.SUCCEDED;
    }

    @Override
    public EncryptedContent<PanicPublicKey> getPanicPublicKey() {
        if (mPanicPublicKey != null) {
            EncryptedContent<PanicPublicKey> ret = new EncryptedContent<>();
            try {
                PanicPublicKey content = new PanicPublicKey();
                content.key = CipherUtils.encodeBytesToBase64String(mPanicPublicKey);
                ret.setContent(content, mGson);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
            return ret;
        }
        return null;
    }

    private void performSetAdminPrivateKey(String newKey) throws Exception {
        byte[] key_bytes = CipherUtils.encodeBase64StringToBase64Bytes(newKey);
        if (key_bytes == null)
            throw new Exception();
        CipherUtils.newPublicKeyFromBytes(key_bytes, CipherUtils.Algorithm.RSA);
        mAdminPublicKey = key_bytes;
    }

    @Override
    public ErrorCode setAdminPublicKey(EncryptedContent<AdminPublicKey> encryptedKey) {
        if (mAdminPublicKey == null) {
            AdminPublicKey content = null;
            try {
                content = encryptedKey.getContent(mGson);
                performSetAdminPrivateKey(content.key);
            } catch (Exception e) {
                e.printStackTrace();
                return ErrorCode.INVALID_PARAMS;
            }
        } else {
            try {
                Cipher decrypter = CipherUtils.generateDecrypterFromBase64PublicKey(mPanicPublicKey, CipherUtils.Algorithm.RSA);
                AdminPublicKey content = encryptedKey.getContent(decrypter, mGson);
                performSetAdminPrivateKey(content.key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return ErrorCode.SUCCEDED;
    }

    @Override
    public String getRandomPublicKeyName() {
        synchronized (mKeyList) {
            int key_index = -1;
            if (mKeyList.size() < MAX_KEY_COUNT) {
                try {
                    UUID uuid = UUID.randomUUID();
                    KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
                    KeyRecord record = new KeyRecord();
                    record.name = uuid.toString();
                    record.keys = pair;
                    record.encrypter = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPublic());
                    record.decrypter = CipherUtils.getDecrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
                    record.publicKeyBase64String = CipherUtils.encodeToBase64String(pair.getPublic());
                    key_index = mKeyList.size();
                    mKeyList.add(record);
                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                }
            } else {
                key_index = mRandom.nextInt() % MAX_KEY_COUNT;
            }
            return mKeyList.get(key_index).name;
        }
    }

    @Override
    public KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value) {
        try {
            KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public NamedPublicKey getServerPublicKey(String name) {
        synchronized (mKeyList) {
            KeyRecord k = getKeyRecord(name);
            if (k != null) {
                NamedPublicKey ret = new NamedPublicKey();
                ret.key = k.publicKeyBase64String;
                return ret;
            }
        }
        return null;
    }

    public KeyRecord getKeyRecord(String keyName) {
        for (KeyRecord k : mKeyList)
            if (StringUtils.equals(keyName, k.name))
                return k;
        return null;
    }

    @Override
    public String encrypt(Object objectToEncrypt, String keyName) {
        synchronized (mKeyList) {
            KeyRecord k = getKeyRecord(keyName);
            if (k != null) {
                try {
                    if (k.encrypter != null)
                        return ContentEncrypter.encryptContent(objectToEncrypt, k.encrypter, mGson);
                    else
                        return ContentEncrypter.encryptContent(objectToEncrypt, mGson);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    @Override
    public <T> T decrypt(String objectToDecrypt, Class<T> aClass, String keyName) {
        synchronized (mKeyList) {
            KeyRecord k = getKeyRecord(keyName);
            if (k != null) {
                try {
                    if (k.decrypter != null)
                        return ContentEncrypter.decryptContent(aClass, objectToDecrypt, k.decrypter, mGson);
                    else
                        return ContentEncrypter.decryptContent(aClass, objectToDecrypt, mGson);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    @Override
    public void close() throws Exception {

    }
}
