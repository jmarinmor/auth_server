package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.*;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.contents.*;
import com.auth.interop.requests.RegistrationRequest;
import com.google.gson.Gson;
import com.jcore.utils.TimeUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class AuthDatabaseImplementationRAM implements AuthDatabase {

    private class UserRecord {
        private String userData;
        private String keyName;
        private String phoneHash;
        private String mailHash;
        private String passwordHash;
    }

    private static List<UserRecord> mUserList = new ArrayList<>();
    private static Gson mGson = new Gson();

    private static RegistrationRequest.PreferedRagistrationMode getPreferedRegistrationMode(RegistrationRequest registrationRequest) {
        if (registrationRequest.preferedRagistrationMode != null) {
            return registrationRequest.preferedRagistrationMode;
        } else {
            if (registrationRequest.phone != null)
                return RegistrationRequest.PreferedRagistrationMode.PHONE;
            if (registrationRequest.mail != null)
                return RegistrationRequest.PreferedRagistrationMode.MAIL;
        }
        return RegistrationRequest.PreferedRagistrationMode.NOT_AVAILABLE;
    }

    @Override
    public ErrorCode setAlive(SetAlive value) {
        return null;
    }

    @Override
    public ErrorCode panic() {
        return null;
    }

    @Override
    public ErrorCode addUserPropertyField(EncryptedContent<AddUserField> content) {
        return null;
    }

    @Override
    public UserFields getUserPropertyFields() {
        return null;
    }

    @Override
    public ErrorCode registerInquiry(Inquiry inquiry) {
        return null;
    }

    @Override
    public ErrorCode sendInquiry(Inquiry.Reason reason, Validator validator) {
        return null;
    }

    @Override
    public UUID verifyUser(Validator validator) {
        return null;
    }

    @Override
    public ErrorCode updateUser(User user, Validator validator) {
        return null;
    }

    @Override
    public User getUser(Validator validator) {
        return null;
    }

    @Override
    public void updateUserPassword(String newPassword, Validator validator) {
        UserRecord user_record = getUserRecord(validator);
        if (user_record != null) {
            String password_hash = DigestUtils.sha256Hex(newPassword);
            user_record.passwordHash = password_hash;
        }
    }

    @Override
    public ErrorCode grantApplicationForUser(Validator validator, String appCode) {
        return null;
    }

    private UserRecord getUserRecord(Validator validator) {
        if (validator.password != null) {
            String password_hash = DigestUtils.sha256Hex(validator.password);
            for (UserRecord user : mUserList) {
                if (StringUtils.equals(user.passwordHash, password_hash)) {
                    return user;
                }
            }
        }
        return null;
    }

    private User decryptUser(KeyDatabase keyDatabase, UserRecord record) {
        User user = keyDatabase.decrypt(record.userData, User.class, record.keyName);
        return user;
    }

    @Override
    public Token generateTokenForUser(KeyDatabase keyDatabase, Validator validator) {
        synchronized (mUserList) {
            if (mUserList.size() == 0) {
                if (StringUtils.equals(validator.password, "12345")) {
                    String userData;
                    String key_name = keyDatabase.getRandomPublicKeyName();
                    {
                        User user = new User();
                        user.id = UUID.randomUUID();
                        user.setName("admin");
                        user.type = User.Type.ADMIN;
                        userData = keyDatabase.encrypt(user, key_name);
                    }
                    String sha256hex = DigestUtils.sha256Hex(validator.password);

                    UserRecord record = new UserRecord();
                    record.userData = userData;
                    record.passwordHash = sha256hex;
                    record.keyName = key_name;
                    mUserList.add(record);

                    return generateTokenForUser(keyDatabase, validator);
               }
            } else {
                UserRecord user_record = getUserRecord(validator);
                if (user_record != null) {
                    Token.UserData data = new Token.UserData();
                    User user = decryptUser(keyDatabase, user_record);
                    data.values = user.values;
                    data.date = TimeUtils.now();
                    data.applicationCode = null;
                    data.applicationName = null;

                    try {
                        Token ret = new Token();
                        ret.serverPublicKeyName = null;
                        ret.userData = keyDatabase.encrypt(data, user_record.keyName);
                        return ret;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public void close() throws Exception {

    }
}
