package com.auth.authServer.model;

import com.auth.interop.User;
import com.auth.interop.UserLogin;

public interface PrivateServer {
    String getPublicKey();
    void sendVerifyUser(boolean useEmail, boolean usePhone);
    String loginWithMail(String app, AuthDatabase database, String email, String password);
    String loginWithPhone(String app, AuthDatabase database, String phone, String code);

}
