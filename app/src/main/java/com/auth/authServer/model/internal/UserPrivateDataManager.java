package com.auth.authServer.model.internal;

import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.internal.AESUtil;
import com.auth.interop.User;
import com.auth.interop.UserLogin;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class UserPrivateDataManager implements PrivateServer {

    private final static String salt = "12345678";
    private final static IvParameterSpec ivParameterSpec = AESUtil.generateIv();
    private static MessageDigest messageDigest;

    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    private static String performCypher(String plainText, String password) {
        try {
            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
            String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
            return cipherText;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String performUncypher(String cipherText, String password) {
        try {
            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
            String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText, key, ivParameterSpec);
            return decryptedCipherText;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(n);
            SecretKey key = keyGenerator.generateKey();
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public User.Record generateUser(User.Data user) {

        synchronized (messageDigest) {
            User.Record usr = new User.Record();
            usr.gid = UUID.randomUUID();
            usr.id = usr.gid.getLeastSignificantBits();
            if (user.mail != null) {
                messageDigest.update(user.mail.getBytes());
                usr.mail = performCypher(user.mail, user.mail);
                usr.mail_hash = new String(messageDigest.digest());
            }
            if (user.phone != null) {
                messageDigest.update(user.phone.getBytes());
                usr.phone = performCypher(user.phone, user.phone);
                usr.phone_hash = new String(messageDigest.digest());
            }
            if (user.password != null) {
                messageDigest.update(user.password.getBytes());
                usr.password = performCypher(user.password, user.password);
                usr.password_hash = new String(messageDigest.digest());
            }
            if (user.password != null) {
                messageDigest.update(user.name.getBytes());
                usr.name = new String(messageDigest.digest());
            }
        }
        return null;
    }

    @Override
    public void sendVerifyUser(boolean useEmail, boolean usePhone) {

    }

    @Override
    public UserLogin loginWithMail(String app, AuthDatabase database, String email, String password) {
        if (email == null || password == null)
            return false;
        synchronized (messageDigest) {
            messageDigest.update(email.getBytes());
            String hash = new String(messageDigest.digest());
            User.Record usr = database.getUserWithEmailHash(hash);
            String m = performUncypher(usr.mail, email);
            String p = performUncypher(usr.password, password);
            String n = performUncypher(usr.name, password);

            if (StringUtils.equals(m, email) && StringUtils.equals(p, password))
                return new UserLogin(n, app);
            return null;
        }
    }
}
