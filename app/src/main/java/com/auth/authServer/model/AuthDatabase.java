package com.auth.authServer.model;

import com.auth.interop.Captcha;
import com.auth.interop.User;
import com.auth.interop.UserStatus;

import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {

    UserStatus getUserStatus(Long id, UUID gid);
    UserStatus getUserStatusByInquiryKey(String key);
    void setUserStatus(UserStatus status);
    void removeUserStatusWithInquiryKey(String inquiryKey);

    User decodeUser(byte[] data, String privateKey);
    byte[] encodeUser(User user, String privateKey);
}
