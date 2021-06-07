package com.auth.authServer.model.implementations;

import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.Captcha;
import com.auth.interop.User;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyPairGenerator;
import java.util.*;

public class AuthDatabaseImplementationRAM implements AuthDatabase {

    private static class UserInfo {
        public String name;
    }

    private Map<String, String> mCaptchaMap = new HashMap<>();
    public boolean mDebugMode = true;
    public List<UserInfo> mUserList = new ArrayList<>();
    //Creating KeyPair generator object
    protected KeyPairGenerator mKeyPairGen;
    private List<User.Record> user = new ArrayList<>();

    public AuthDatabaseImplementationRAM() {
        //Initializing the KeyPairGenerator
        //mKeyPairGen = KeyPairGenerator.getInstance("DSA");
        //mKeyPairGen.initialize(2048);
    }


    @Override
    public boolean verifyCaptcha(String key, String value) {
        String v;
        synchronized (mCaptchaMap) {
            v = mCaptchaMap.get(key);
            mCaptchaMap.remove(key);
        }
        return StringUtils.equals(value, v);
    }

    @Override
    public int getUserCount() {
        synchronized (mUserList) {
            return mUserList.size();
        }
    }

    @Override
    public Long addUser(User.Data user) {
        return null;
    }

    @Override
    public void verifyUser(String emailCode, String phoneCode) {

    }

    @Override
    public boolean loginByPasword(String password) {
        return false;
    }
}
