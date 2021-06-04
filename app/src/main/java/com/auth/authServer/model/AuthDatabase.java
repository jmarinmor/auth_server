package com.auth.authServer.model;

import com.auth.interop.App;
import com.auth.interop.Captcha;
import com.auth.interop.User;

public interface AuthDatabase {
    Captcha demandNewCaptcha();
    boolean verifyCaptcha(String key, String value);
    int getUserCount();
    Long addUser(User.Data user);
    void verifyUser(String emailCode, String phoneCode);
    boolean loginByPasword(String password);
    User.Record getUserWithEmailHash(String hash);
}
