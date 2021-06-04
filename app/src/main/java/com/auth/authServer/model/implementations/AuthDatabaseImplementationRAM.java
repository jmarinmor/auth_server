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
    protected static Random mRandom = new Random();
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

    protected static String generateCaptcha(int size) {

//        char data[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
//                'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
//                'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
//                'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
//                'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6',
//                '7', '8', '9' };
        char data[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
                'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6',
                '7', '8', '9' };
        char index[] = new char[size];

        int i = 0;

        synchronized (mRandom) {
            for (i = 0; i < index.length; i++) {
                int ran = mRandom.nextInt(data.length);
                index[i] = data[ran];
            }
        }
        return new String(index);
    }

    @Override
    public Captcha demandNewCaptcha() {
        Captcha ret = new Captcha();
        String key = generateCaptcha(5);
        String value = generateCaptcha(5);

        ret.id = key;
        if (mDebugMode)
            ret.desiredResult = value;
        synchronized (mCaptchaMap) {
            mCaptchaMap.put(key, value);
        }
        return ret;
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
