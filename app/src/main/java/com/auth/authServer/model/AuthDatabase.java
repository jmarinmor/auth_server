package com.auth.authServer.model;

import com.auth.interop.Captcha;
import com.auth.interop.User;
import com.auth.interop.UserStatus;

import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {
    Captcha demandNewCaptcha();
    boolean verifyCaptcha(String key, String value);
    int getUserCount();
    Long addUser(User.Data user);
    void verifyUser(String emailCode, String phoneCode);
    boolean loginByPasword(String password);
    User.Record getUserWithEmailHash(String hash);


    UserStatus getUserStatus(Long id, UUID gid);
    UserStatus getUserStatusByInquiryKey(String key);
    void setUserStatus(UserStatus status);
    void removeUserStatusWithInquiryKey(String inquiryKey);

    User decodeUser(byte[] data, String privateKey);
    byte[] encodeUser(User user, String privateKey);
}
