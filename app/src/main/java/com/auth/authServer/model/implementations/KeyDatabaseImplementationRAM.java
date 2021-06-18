package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.NamedPublicKey;
import com.auth.interop.contents.*;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
import com.jcore.utils.CipherUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyPair;
import java.util.*;

public class KeyDatabaseImplementationRAM implements KeyDatabase {

    public final int MAX_KEY_COUNT = 2;

    private byte[] mAdminPublicKey;
    private Random mRandom = new Random();

    private Map<String, byte[]> mPublicKey = new HashMap();
    private Map<String, byte[]> mPrivateKey = new HashMap();
    private Map<String, byte[]> mEncryptedPrivateKey = new HashMap();
    private boolean mInPanic;

    private Gson mGson = new Gson();

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
    public String getRandomPublicKeyName() {
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
    public KeyPair generateKeyPair() {
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
    public String encrypt(Object objectToEncrypt, String keyName) {
        byte[] bytes = getPublicKeyBytes(keyName);
        if (bytes != null) {
            try {
                Crypter.Encrypter encrypter = Crypter.Encrypter.newFromRSAPublicKey(bytes);
                return ContentEncrypter.encryptContent(objectToEncrypt, encrypter, mGson);
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
    public <T> T decrypt(String objectToDecrypt, Class<T> aClass, String keyName) {
        byte[] bytes = getPrivateKeyBytes(keyName);
        if (bytes != null) {
            try {
                Crypter.Decrypter decrypter = Crypter.Decrypter.newFromRSAPrivateKey(bytes);
                return ContentEncrypter.decryptContent(aClass, objectToDecrypt, decrypter, mGson);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public void close() throws Exception {

    }
}
