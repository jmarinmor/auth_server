package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.*;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.contents.*;
import com.auth.interop.requests.RegistrationRequest;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
import com.jcore.utils.CipherUtils;
import com.jcore.utils.TimeUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import java.util.*;

public class AuthDatabaseImplementationRAM implements AuthDatabase {

    private class UserRecord {
        private String protectedData;
        private Map<String, String> resources;
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
    public ErrorCode executeAdminCommand(String command, KeyDatabase keyDatabase) {
        if (keyDatabase == null)
            return ErrorCode.INVALID_PARAMS;
        ErrorCode e = keyDatabase.executeAdminCommand(command);
        if (e != ErrorCode.SUCCEDED && e != ErrorCode.NON_ATTENDED)
            return e;
        if (e == ErrorCode.NON_ATTENDED) {
            AdminCommand cmd = keyDatabase.decryptAdminCommand(command);
            if (cmd != null) {
                switch (cmd.type) {
                    case ADD_USER_FIELD:
                        break;
                }
            }
        }
        return ErrorCode.SUCCEDED;
    }

    @Override
    public ErrorCode panic() {
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
    public ErrorCode updateUser(User.PublicData user, KeyDatabase keyDatabase, Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User.ProtectedData stored_user = keyDatabase.decrypt(record.protectedData, User.ProtectedData.class, record.keyName);
            if (!stored_user.id.equals(user.id))
                return ErrorCode.INVALID_USER;

            Map<String, String> values = new HashMap<>();
            Map<String, UUID> resources = new HashMap<>();

            if (user.values != null) {
                for (Map.Entry<String, String> entry : user.values.entrySet()) {
                    if (record.resources != null && record.resources.containsKey(entry.getKey())) {
                        // It is a resource
                        // TODO: 15/06/2021 Encrypt with a symmetric key
                    } else {
                        values.put(entry.getKey(), entry.getValue());
                    }
                }
            }

            stored_user.values = values;
            stored_user.resources = resources;

            if (stored_user.type == User.Type.ADMIN && !StringUtils.equals(stored_user.publicKey, user.publicKey)) {
                return ErrorCode.OPERATION_NOT_ALLOWED;
//                try {
//                    AdminPublicKeyContainer container = new AdminPublicKeyContainer();
//                    AdminPublicKey content = new AdminPublicKey();
//                    content.key = user.publicKey;
//                    if (stored_user.publicKey != null) {
//                        Crypter.Encrypter cipher = Crypter.Encrypter.newFromRSABase64PublicKey(stored_user.publicKey);
//                        container.setContent(content, cipher, mGson);
//                    } else
//                        container.setContent(content, mGson);
//                    keyDatabase.setAdminPublicKey(container);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                    return ErrorCode.INVALID_USER;
//                }
            }

            stored_user.publicKey = user.publicKey;
            String userData = keyDatabase.encrypt(stored_user, record.keyName);
            record.protectedData = userData;

            return ErrorCode.SUCCEDED;
        }
        return ErrorCode.INVALID_USER;
    }

    @Override
    public User.PublicData getUser(KeyDatabase keyDatabase, Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User.ProtectedData user = keyDatabase.decrypt(record.protectedData, User.ProtectedData.class, record.keyName);
            User.PublicData ret;
            {
                String json = mGson.toJson(user);
                ret = mGson.fromJson(json, User.PublicData.class);
            }
            return ret;
        }
        return null;
    }

    @Override
    public ErrorCode updateUserValidator(String newPassword, Validator validator, Validator newValidator){
        UserRecord user_record = getUserRecord(validator);
        if (user_record != null) {
            if (newValidator.password != null) {
                String hash = DigestUtils.sha256Hex(newValidator.password);
                user_record.passwordHash = hash;
            }
            if (newValidator.phone != null) {
                String hash = DigestUtils.sha256Hex(newValidator.phone);
                user_record.phoneHash = hash;
            }
            if (newValidator.mail != null) {
                String hash = DigestUtils.sha256Hex(newValidator.mail);
                user_record.mailHash = hash;
            }
            return ErrorCode.SUCCEDED;
        }
        return ErrorCode.INVALID_USER;
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

    @Override
    public Token generateTokenForUser(KeyDatabase keyDatabase, Validator validator) {
        synchronized (mUserList) {
            if (mUserList.size() == 0) {
                if (StringUtils.equals(validator.password, "12345")) {
                    String userData;
                    String key_name = keyDatabase.getRandomPublicKeyName();
                    {
                        User.ProtectedData user = new User.ProtectedData();
                        user.id = UUID.randomUUID();
                        user.setName("admin");
                        user.type = User.Type.ADMIN;
                        userData = keyDatabase.encrypt(user, key_name);
                    }
                    String sha256hex = DigestUtils.sha256Hex(validator.password);

                    UserRecord record = new UserRecord();
                    record.protectedData = userData;
                    record.passwordHash = sha256hex;
                    record.keyName = key_name;
                    mUserList.add(record);

                    return generateTokenForUser(keyDatabase, validator);
               }
            } else {
                UserRecord user_record = getUserRecord(validator);
                if (user_record != null) {
                    Token.UserData data = new Token.UserData();
                    User.ProtectedData user = keyDatabase.decrypt(user_record.protectedData, User.ProtectedData.class, user_record.keyName);
                    data.values = user.values;
                    data.date = TimeUtils.now();
                    data.applicationCode = null;
                    data.applicationName = null;

                    try {
                        Token ret = new Token();
                        ret.serverPublicKeyName = user_record.keyName;
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
