package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
import com.jcore.utils.CipherUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyPair;
import java.util.*;

public class KeyDatabaseImplementationRAM implements KeyDatabase {

    private static class KeyRecord {
        private String name;
        private boolean inPanic;
        private String publicKeyBase64String;
        private Crypter.Encrypter encrypter;
        private Crypter.Decrypter decrypter;
    }

    public final int MAX_KEY_COUNT = 2;

    private static byte[] mAdminPublicKey;
    private static Random mRandom = new Random();
    private static List<KeyRecord> mKeyList = new ArrayList<>();

    private static Gson mGson = new Gson();

    @Override
    public ErrorCode executeAdminCommand(String commandToDecrypt) {
        AdminCommand command = privateToCommand(commandToDecrypt);
        if (command == null)
            return ErrorCode.INVALID_PARAMS;
        switch (command.type) {
            case SET_PUBLIC_KEY: {
                byte[] key_bytes = CipherUtils.encodeBase64StringToBase64Bytes(command.publicKey);
                mAdminPublicKey = key_bytes;
                try {
                    Crypter.Decrypter.newFromRSAPublicKey(mAdminPublicKey);
                    return ErrorCode.SUCCEDED;
                } catch (Exception e) {
                    e.printStackTrace();
                    return ErrorCode.INVALID_PARAMS;
                }
                //break;
            }
        }
        return ErrorCode.NON_ATTENDED;
    }

    private AdminCommand privateToCommand(String commandToDecrypt) {
        AdminCommand command = null;
        if (mAdminPublicKey == null) {
            try {
                command = ContentEncrypter.decryptContent(AdminCommand.class, commandToDecrypt, mGson);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try {
                Crypter.Decrypter decrypter = Crypter.Decrypter.newFromRSAPublicKey(mAdminPublicKey);
                command = ContentEncrypter.decryptContent(AdminCommand.class, commandToDecrypt, decrypter, mGson);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return command;
    }

    @Override
    public AdminCommand decryptAdminCommand(String commandToDecrypt) {
        AdminCommand command = privateToCommand(commandToDecrypt);
        return command;
    }

    @Override
    public void panic() {
        if (mAdminPublicKey != null) {
            synchronized (mKeyList) {
                try {
                    Crypter.Encrypter encrypter = Crypter.Encrypter.newFromRSAPublicKey(mAdminPublicKey);
                    for (int i = 0; i < mKeyList.size(); i++) {
                        KeyRecord k = mKeyList.get(i);
                        if (!k.inPanic) {
                            k.inPanic = true;
                            //s = encrypter
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
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
                    record.encrypter = Crypter.Encrypter.newFromRSAKey(pair.getPublic());
                    record.decrypter = Crypter.Decrypter.newFromRSAKey(pair.getPrivate());
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
