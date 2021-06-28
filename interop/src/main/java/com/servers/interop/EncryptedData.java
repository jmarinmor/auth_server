package com.servers.interop;

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class EncryptedData {
    private static final String ALGORITHM_SIGNATURE = "SHA1withRSA";
    // bouncycastle provider
    private static final String SECURITY_PROVIDER = "BC";
    // RSA settings
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_RSA_CIPHER = "RSA/None/NoPadding";
    private static final int ALGORITHM_RSA_KEYSIZE = 2048;
    // AES settings
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_AES_CIPHER = "AES/CBC/PKCS7Padding";
    private static final int ALGORITHM_AES_KEYSIZE = 256;

    private static KeyPairGenerator keyPairGeneratorClient;
    private static KeyGenerator mSymmetricalKeyGenerator;
    private static SecureRandom mSecureRandom;
    private static Signature mSignature;

    static {
        try {
            keyPairGeneratorClient = KeyPairGenerator.getInstance(ALGORITHM_RSA);
            keyPairGeneratorClient.initialize(ALGORITHM_RSA_KEYSIZE);

            mSymmetricalKeyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
            mSymmetricalKeyGenerator.init(ALGORITHM_AES_KEYSIZE);

            mSecureRandom = new SecureRandom();

            mSignature = Signature.getInstance(ALGORITHM_SIGNATURE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generatePair() {
        KeyPair keyPairClient = keyPairGeneratorClient.generateKeyPair();
        return keyPairClient;
    }

    public static class Encrypter {
        private Key mPrivateKey;
        private SecretKey mSimmetricalKey;
        private Cipher mRSACipher;
        private Cipher mAESCipher;
        private IvParameterSpec ivParameterClient;

        public Encrypter(Key key) throws Exception {
            this.mPrivateKey = key;
            this.mSimmetricalKey = mSymmetricalKeyGenerator.generateKey();
            this.mRSACipher = Cipher.getInstance(ALGORITHM_RSA_CIPHER, SECURITY_PROVIDER);
            this.mAESCipher = Cipher.getInstance(ALGORITHM_AES_CIPHER, SECURITY_PROVIDER);

            mRSACipher.init(Cipher.WRAP_MODE, mPrivateKey);
            ivParameterClient = new IvParameterSpec(mSecureRandom.generateSeed(16));
            mAESCipher.init(Cipher.ENCRYPT_MODE, mSimmetricalKey, ivParameterClient);
        }

        public EncryptedData encrypt(String text) throws Exception {
            byte[] plain = text.getBytes(StandardCharsets.UTF_8);
            EncryptedData ret = new EncryptedData();

            // crypt text
            {
                ret.encryptedData = mAESCipher.doFinal(plain);
                ret.iv = ivParameterClient.getIV();
            }

            // crypt aes key
            {
                ret.encryptedKey = mRSACipher.wrap(mSimmetricalKey);
            }


            // calculate digest
            {
                byte[] digest = DigestUtils.sha256(plain);
                ret.signature = mRSACipher.doFinal(digest);
            }

            return ret;
        }
    }

    public byte[] signature;
    public byte[] encryptedKey;
    public byte[] encryptedData;
    public byte[] iv;


    public String decrypt(PublicKey publicKey) throws Exception {
        return null;
        /*
        // unwrap aes key
        mRSACipher.init(Cipher.UNWRAP_MODE, publicKey);
        SecretKey decryptedKey = (SecretKey) mRSACipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);

        // decrypt text
        IvParameterSpec ivParameterSpecServer = new IvParameterSpec(iv);
        mAESCipher.init(Cipher.DECRYPT_MODE, decryptedKey, ivParameterSpecServer);
        byte[] decyptedData = mAESCipher.doFinal(encryptedData);

        /*
        // calculate digest
        byte[] digest = DigestUtils.sha256(decyptedData);

        // verify signature from digest
        mSignature.initVerify(publicKeyClient);
        mSignature.update(digestServer);

        // validate signature
        Assert.assertTrue("valid signature(" + Base64.toBase64String(serializedEncryptedData.signature) + ") from client", signatureServer.verify(serializedEncryptedData.signature));

        // validate decrypted text
        if (signatureServer.verify(serializedEncryptedData.signature)) {
            Data decryptedData = (Data) SerializationUtils.deserialize(decyptedData);
            Assert.assertEquals("decypted text same as original", decryptedData.msg, text);
        }

         */
    }
}
