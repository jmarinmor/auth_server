package com.auth.interop.utils;

import com.auth.interop.NamedPublicKey;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CipherUtils {

    public enum Algorithm {
        RSA("RSA");

        private String value;
        Algorithm(String value) {this.value = value;}

        public String getValue() {
            return value;
        }
    }

    public static PrivateKey newPrivateKeyFromBytes(byte[] bytes, Algorithm algorithm) throws Exception {
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        String algo = algorithm.getValue();
        KeyFactory kf = KeyFactory.getInstance(algo);
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

    public static PublicKey newPublicKeyFromBytes(byte[] bytes, Algorithm algorithm) throws Exception {
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        String algo = algorithm.getValue();
        KeyFactory kf = KeyFactory.getInstance(algo);
        PublicKey pub = kf.generatePublic(ks);
        return pub;
    }

    public static String getPublicKeyInBase64(KeyPair pair) {
        PublicKey key = pair.getPublic();
        byte[] data = key.getEncoded();
        String key64 = Base64.getEncoder().encodeToString(data);
        return key64;
    }

    public static String getPrivateKeyInBase64(KeyPair pair) {
        PrivateKey key = pair.getPrivate();
        byte[] data = key.getEncoded();
        String key64 = Base64.getEncoder().encodeToString(data);
        return key64;
    }

    public static Cipher generateDecrypterFromBase64PrivateKey(String key, Algorithm algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PrivateKey pk = newPrivateKeyFromBytes(keyBytes, algorithm);
        return getDecrypter(algorithm, pk);
    }

    public static Cipher generateDecrypterFromBase64PublicKey(String key, Algorithm algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PublicKey pk = newPublicKeyFromBytes(keyBytes, algorithm);
        return getDecrypter(algorithm, pk);
    }

    public static Cipher generateEncrypterFromBase64PrivateKey(String key, Algorithm algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PrivateKey pk = newPrivateKeyFromBytes(keyBytes, algorithm);
        return getEncrypter(algorithm, pk);
    }

    public static Cipher generateEncrypterFromBase64PublicKey(String key, Algorithm algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PublicKey pk = newPublicKeyFromBytes(keyBytes, algorithm);
        return getEncrypter(algorithm, pk);
    }

    public static void save1(PublicKey publicKey) throws Exception {
        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(publicKey.getEncoded());
        }
    }

    public static void load1() throws Exception {
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
    }

    public static void join1() {
        //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        //keyFactory.generatePublic(publicKeySpec);
    }

    public static Cipher getEncrypter(Algorithm algorithm, Key key) throws Exception {
        String algo = algorithm.getValue();
        Cipher cipher = Cipher.getInstance(algo);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    public static Cipher getDecrypter(Algorithm algorithm, Key key) throws Exception {
        String algo = algorithm.getValue();
        Cipher cipher = Cipher.getInstance(algo);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
    }

    public static byte[] encrypt(Algorithm algorithm, String data, PublicKey publicKey) throws Exception {
        String algo = algorithm.getValue();
        Cipher cipher = Cipher.getInstance(algo);
        //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static String decryptToString(Algorithm algorithm, byte[] data, PrivateKey privateKey) throws Exception {
        String algo = algorithm.getValue();
        Cipher cipher = Cipher.getInstance(algo);
        //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static KeyPair generateKeyPair(Algorithm algorithm) throws Exception {
        String algo = algorithm.getValue();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        kpg.initialize(2048, random);
        //kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();
        return kp;
//        PublicKey pub = kp.getPublic();
//        PrivateKey pvt = kp.getPrivate();

//        String outFile = ...;
//        out = new FileOutputStream(outFile + ".key");
//        out.write(pvt.getEncoded());
//        out.close();

//        /* Read all bytes from the private key file */
//        Path path = Paths.get(keyFile);
//        byte[] bytes = Files.readAllBytes(path);
//        /* Generate private key. */
//        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PrivateKey pvt = kf.generatePrivate(ks);

//        /* Read all the public key bytes */
//        Path path = Paths.get(keyFile);
//        byte[] bytes = Files.readAllBytes(path);
//        /* Generate public key. */
//        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PublicKey pub = kf.generatePublic(ks);

//        System.out.println("Private key format: " + pvt.getFormat());
//        // prints "Private key format: PKCS#8" on my machine
//        System.out.println("Public key format: " + pub.getFormat());
//        // prints "Public key format: X.509" on my machine

    }

//
//    private final static String salt = "12345678";
//    private final static IvParameterSpec ivParameterSpec = AESUtil.generateIv();
//    private static MessageDigest messageDigest;
//
//    static {
//        try {
//            messageDigest = MessageDigest.getInstance("SHA-256");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//    }
//
//    private static String performCypher(String plainText, String password) {
//        try {
//            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
//            String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
//            return cipherText;
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//
//    private static String performUncypher(String cipherText, String password) {
//        try {
//            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
//            String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText, key, ivParameterSpec);
//            return decryptedCipherText;
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//
//    private static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
//        try {
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            keyGenerator.init(n);
//            SecretKey key = keyGenerator.generateKey();
//            return key;
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//
//    @Override
//    public User.Record generateUser(User.Data user) {
//
//        synchronized (messageDigest) {
//            User.Record usr = new User.Record();
//            usr.gid = UUID.randomUUID();
//            usr.id = usr.gid.getLeastSignificantBits();
//            if (user.mail != null) {
//                messageDigest.update(user.mail.getBytes());
//                usr.mail = performCypher(user.mail, user.mail);
//                usr.mail_hash = new String(messageDigest.digest());
//            }
//            if (user.phone != null) {
//                messageDigest.update(user.phone.getBytes());
//                usr.phone = performCypher(user.phone, user.phone);
//                usr.phone_hash = new String(messageDigest.digest());
//            }
//            if (user.password != null) {
//                messageDigest.update(user.password.getBytes());
//                usr.password = performCypher(user.password, user.password);
//                usr.password_hash = new String(messageDigest.digest());
//            }
//            if (user.password != null) {
//                messageDigest.update(user.name.getBytes());
//                usr.name = new String(messageDigest.digest());
//            }
//        }
//        return null;
//    }
//
//    @Override
//    public void sendVerifyUser(boolean useEmail, boolean usePhone) {
//
//    }
//
//    @Override
//    public UserLogin loginWithMail(String app, AuthDatabase database, String email, String password) {
//        if (email == null || password == null)
//            return false;
//        synchronized (messageDigest) {
//            messageDigest.update(email.getBytes());
//            String hash = new String(messageDigest.digest());
//            User.Record usr = database.getUserWithEmailHash(hash);
//            String m = performUncypher(usr.mail, email);
//            String p = performUncypher(usr.password, password);
//            String n = performUncypher(usr.name, password);
//
//            if (StringUtils.equals(m, email) && StringUtils.equals(p, password))
//                return new UserLogin(n, app);
//            return null;
//        }
//    }
}
