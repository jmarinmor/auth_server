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

    private static class UserRecord {
        private String protectedData;
        private Map<String, String> resources;
        private String keyName;
        private String phoneHash;
        private String mailHash;
        private String passwordHash;
    }

    private static class InquiryRecord {
        private String key;
        private String value;
        private Inquiry.Action action;
        private Inquiry.ActionParams params;
    }

    private static List<InquiryRecord> mInquiryList = new ArrayList<>();
    private static List<UserRecord> mUserList = new ArrayList<>();
    private static Gson mGson = new Gson();
    private KeyDatabase mKeyDatabase;


    public AuthDatabaseImplementationRAM(KeyDatabase keyDatabase) {
        mKeyDatabase = keyDatabase;
    }

    @Override
    public ErrorCode executeAdminCommand(String command) {
        if (mKeyDatabase == null)
            return ErrorCode.INVALID_PARAMS;
        ErrorCode e = mKeyDatabase.executeAdminCommand(command);
        if (e != ErrorCode.SUCCEDED && e != ErrorCode.NON_ATTENDED)
            return e;
        if (e == ErrorCode.NON_ATTENDED) {
            AdminCommand cmd = mKeyDatabase.decryptAdminCommand(command);
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
    public Inquiry.Response registerInquiry(Inquiry inquiry, Inquiry.Action action, Inquiry.ActionParams params) {
        Inquiry.Response response = new Inquiry.Response();
        if (inquiry == null || action == null) {
            response.errorCode = ErrorCode.INVALID_PARAMS;
            return response;
        }

        InquiryRecord record = new InquiryRecord();
        record.key = inquiry.inquiry;
        record.value = inquiry.desiredResult;
        record.action = action;
        record.params = params;
        synchronized (mInquiryList) {
            mInquiryList.add(record);
        }
        response.errorCode = ErrorCode.SUCCEDED;
        if (USE_DEBUG_INFO) {
            response.debugDesiredResponse = new Inquiry(inquiry.inquiry, inquiry.desiredResult);
        }
        return response;
    }

    private void executeAction(Inquiry.Action action, Inquiry.ActionParams params1, Inquiry.ActionParams params2, Inquiry.Response response) {
        switch (action) {
            case REGISTER_USER:
                // Send verification code
                sendRegisterInquiry(params1, params2, response);
                break;
            case VALIDATE_USER:
                validateUserInquiry(params1, params2, response);
                break;
        }
    }

    @Override
    public Inquiry.Response verifyInquiry(Inquiry inquiry, Inquiry.ActionParams params) {
        Inquiry.Response response = new Inquiry.Response();
        if (inquiry == null) {
            response.errorCode = ErrorCode.INVALID_PARAMS;
            return response;
        }

        synchronized (mInquiryList) {
            for (int i = 0; i < mInquiryList.size(); i++) {
                InquiryRecord record = mInquiryList.get(i);
                if (StringUtils.equals(inquiry.inquiry, record.key)) {
                    mInquiryList.remove(i);
                    executeAction(record.action, record.params, params, response);
                    break;
                }
            }
        }
        return response;
    }

    private ErrorCode convert(User.PublicData from, User.ProtectedData to) {
        Map<String, String> values = new HashMap<>();
        Map<String, UUID> resources = new HashMap<>();

        if (from.values != null) {
            for (Map.Entry<String, String> entry : from.values.entrySet()) {
                //if (record.resources != null && record.resources.containsKey(entry.getKey())) {
                //    // It is a resource
                //    // TODO: 15/06/2021 Encrypt with a symmetric key
                //} else {
                    values.put(entry.getKey(), entry.getValue());
                //}
            }
        }

        to.values = values;
        to.resources = resources;
        to.publicKey = from.publicKey;

        if (to.type != from.type) {
            if (to.type != User.Type.ADMIN)
                to.type = from.type;
            if (to.type == User.Type.APPLICATION) {
                String sha256hex;
                if (to.id != null)
                    sha256hex = DigestUtils.sha256Hex(to.id.toString());
                else if (from.id != null)
                    sha256hex = DigestUtils.sha256Hex(from.id.toString());
                else
                    return ErrorCode.OPERATION_NOT_ALLOWED;
                to.appCode = sha256hex;
            }
        }

        if (to.type == User.Type.ADMIN && !StringUtils.equals(to.publicKey, from.publicKey))
            return ErrorCode.OPERATION_NOT_ALLOWED;

        return ErrorCode.SUCCEDED;
    }

    private void validateUserInquiry(Inquiry.ActionParams params1, Inquiry.ActionParams params2, Inquiry.Response response) {
        Inquiry.ActionParams params = new Inquiry.ActionParams();
        if (params1 != null && params1.user != null)
            params.user = params1.user;
        if (params2 != null && params2.user != null)
            params.user = params2.user;

        if (params1 != null && params1.validator != null)
            params.validator = params1.validator;
        if (params2 != null && params2.validator != null)
            params.validator = params2.validator;

        if (params.validator == null) {
            response.errorCode = ErrorCode.INVALID_PARAMS;
            return;
        }

        User.ProtectedData usr = new User.ProtectedData();
        usr.id = UUID.randomUUID();
        convert(params.user, usr);
        if (usr.type == User.Type.ADMIN || usr.type == null)
            usr.type = User.Type.USER;

        String userData;
        String key_name = mKeyDatabase.getRandomPublicKeyName();
        userData = mKeyDatabase.encrypt(usr, key_name);

        String sha256hex = DigestUtils.sha256Hex(params.validator.password);
        UserRecord record = new UserRecord();
        record.protectedData = userData;
        record.passwordHash = sha256hex;
        record.keyName = key_name;
        synchronized (mUserList) {
            mUserList.add(record);
        }
        response.id = usr.id;
        response.errorCode = ErrorCode.SUCCEDED;
    }

    private void sendRegisterInquiry(Inquiry.ActionParams params1, Inquiry.ActionParams params2, Inquiry.Response response) {
        Inquiry.ActionParams params = new Inquiry.ActionParams();
        if (params1 != null && params1.user != null)
            params.user = params1.user;
        if (params2 != null && params2.user != null)
            params.user = params2.user;

        if (params1 != null && params1.validator != null)
            params.validator = params1.validator;
        if (params2 != null && params2.validator != null)
            params.validator = params2.validator;

        Inquiry inquiry = Inquiry.generateNewInquiry();
        Inquiry.Response r = registerInquiry(inquiry, Inquiry.Action.VALIDATE_USER, params);
        response.id = r.id;
        response.errorCode = r.errorCode;
        response.debugDesiredResponse = r.debugDesiredResponse;
    }

    @Override
    public ErrorCode updateUser(User.PublicData user, Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User.ProtectedData stored_user = mKeyDatabase.decrypt(record.protectedData, User.ProtectedData.class, record.keyName);
            if (!stored_user.id.equals(user.id))
                return ErrorCode.INVALID_USER;

            ErrorCode r = convert(user, stored_user);
            if (r != ErrorCode.SUCCEDED)
                return r;

            String userData = mKeyDatabase.encrypt(stored_user, record.keyName);
            record.protectedData = userData;

            return ErrorCode.SUCCEDED;
        }
        return ErrorCode.INVALID_USER;
    }

    @Override
    public User.PublicData getUser(Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User.ProtectedData user = mKeyDatabase.decrypt(record.protectedData, User.ProtectedData.class, record.keyName);
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
    public ErrorCode updateUserValidator(Validator validator, Validator newValidator){
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
    public Token generateTokenForUser(Validator validator) {
        synchronized (mUserList) {
            if (mUserList.size() == 0) {
                if (StringUtils.equals(validator.password, "12345")) {
                    String userData;
                    String key_name = mKeyDatabase.getRandomPublicKeyName();
                    {
                        User.ProtectedData user = new User.ProtectedData();
                        user.id = UUID.randomUUID();
                        user.setName("admin");
                        user.type = User.Type.ADMIN;
                        userData = mKeyDatabase.encrypt(user, key_name);
                    }
                    String sha256hex = DigestUtils.sha256Hex(validator.password);

                    UserRecord record = new UserRecord();
                    record.protectedData = userData;
                    record.passwordHash = sha256hex;
                    record.keyName = key_name;
                    mUserList.add(record);

                    return generateTokenForUser(validator);
               }
            } else {
                UserRecord user_record = getUserRecord(validator);
                if (user_record != null) {
                    Token.UserData data = new Token.UserData();
                    User.ProtectedData user = mKeyDatabase.decrypt(user_record.protectedData, User.ProtectedData.class, user_record.keyName);
                    data.values = user.values;
                    data.date = TimeUtils.now();
                    data.applicationCode = null;
                    data.applicationName = null;

                    try {
                        Token ret = new Token();
                        ret.serverPublicKeyName = user_record.keyName;
                        ret.userData = mKeyDatabase.encrypt(data, user_record.keyName);
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

    @Override
    public ErrorCode setUserPublicKey(String publicKey, Validator validator) {
        User.PublicData user = getUser(validator);
        if (user != null) {
            user.publicKey = publicKey;
            return updateUser(user, validator);
        } else
            return ErrorCode.INVALID_USER;
    }

}
