package com.auth.authServer.model.implementations;

import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.*;
import com.auth.interop.contents.*;
import com.jcore.utils.TimeUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

public class AuthDatabaseImplementationRAM extends AuthDatabaseImplementation {

    private static List<InquiryRecord> mInquiryList = new ArrayList<>();
    private static List<UserRecord> mUserList = new ArrayList<>();
    private static Map<Long, String> mValues = new HashMap<>();
    private static Set<String> mUserFields = new HashSet<>();
    private static boolean mUpdatingUsers;
    private static double mUpdateUsersProgression;


    public AuthDatabaseImplementationRAM(KeyDatabase keyDatabase) {
        mKeyDatabase = keyDatabase;
    }

    @Override
    protected boolean containsUserField(String name) {
        synchronized (mUserFields) {
            name = name.toLowerCase();
            return mUserFields.contains(name);
        }
    }

    @Override
    protected void setValue(Long id, Property value, String keyName) {
        synchronized (mValues) {
            String data = null;
            if (value != null)
                data = mKeyDatabase.encryptObjectToBase64(value, keyName, mGson);

            mValues.put(id, data);
        }
    }

    @Override
    protected Long createValueEntry() {
        long id;
        synchronized (mValues) {
            id = mValues.size() + 1;
            mValues.put(id, null);
        }
        return id;
    }

    @Override
    protected double getUpdateUsersProgression() {
        return mUpdateUsersProgression;
    }

    @Override
    protected void performAlterFieldInAllUsers(AlterUserField cmd, boolean add, boolean delete, boolean update) {
        mUpdateUsersProgression = 0.0;
        mUpdatingUsers = true;
        new Thread(() -> {
            synchronized (mUserList) {
                String field_name = cmd.name.toLowerCase();
                if (add) {
                    mUserFields.add(field_name);
                    for (int i = 0; i < mUserList.size(); i++) {
                        UserRecord record = mUserList.get(i);
                        performUpdateUserRecordField(field_name, record);
                        mUpdateUsersProgression = ((double) i) / ((double) mUserList.size());
                    }
                } else if (update) {
                    for (int i = 0; i < mUserList.size(); i++) {
                        UserRecord record = mUserList.get(i);
                        performCheckUserRecordField(field_name, record);
                        mUpdateUsersProgression = ((double) i) / ((double) mUserList.size());
                    }
                } else if (delete) {
                    for (int i = 0; i < mUserList.size(); i++) {
                        UserRecord record = mUserList.get(i);
                        performDeleteUserRecordField(field_name, record);
                        mUpdateUsersProgression = ((double) i) / ((double) mUserList.size());
                    }
                }

                mUpdateUsersProgression = 1.0;
                mUpdatingUsers = false;
            }
        }).start();
    }

    @Override
    public ErrorCode panic() {
        mKeyDatabase.panic();
        return ErrorCode.SUCCEDED;
    }

    @Override
    public Set<String> getUserPropertyFields() {
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

        String key_name = mKeyDatabase.getRandomPublicKeyName(KeyDatabase.Encoding.ASYMMETRIC);

        User usr = new User();
        usr.id = UUID.randomUUID();
        convert(params.user, usr, key_name);
        if (usr.type == User.Type.ADMIN || usr.type == null)
            usr.type = User.Type.USER;

        synchronized (mUserFields) {
            for (String name : mUserFields) {
                Property p = null;
                if (params1 != null && params1.properties != null)
                    p = params1.properties.get(name);
                if (params2 != null && params2.properties != null)
                    p = params2.properties.get(name);
                // TODO: 26/6/21 Faltan los campos detached
                if (p != null) {
                    Long id = createValueEntry();
                    setValue(id, p, key_name);
                }
            }
        }

        String userData;
        userData = mKeyDatabase.encryptObjectToBase64(usr, key_name, mGson);

        String sha256hex = DigestUtils.sha256Hex(params.validator.password);
        UserRecord record = new UserRecord();
        record.userData = userData;
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
    public ErrorCode updateUser(User user, Validator validator) {
        if (user == null)
            return ErrorCode.INVALID_USER;
        if (validator == null)
            return ErrorCode.INVALID_VALIDATOR;

        UserRecord record = getUserRecord(validator);
        if (record != null)
            return performUpdateUserRecord(user, record);
        return ErrorCode.INVALID_USER;
    }

    private User getUserPublicData(UserRecord record) {
        if (record != null) {
            User user = mKeyDatabase.decryptBase64ToObject(record.userData, User.class, record.keyName, mGson);
            User ret;
            {
                String json = mGson.toJson(user);
                ret = mGson.fromJson(json, User.class);
            }
            return ret;
        }
        return null;
    }

    @Override
    public User getUser(Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User ret = getUserPublicData(record);
            ret.valueReferences = null;
            return ret;
        }
        return null;
    }

    @Override
    public Set<String> getUserFields(Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User user = getUserPublicData(record);
            if (user != null) {
                Set<String> ret = user.valueReferences.keySet();

            }
        }
        return null;
    }

    @Override
    public Map<String, Property> getUserProperties(Set<String> names, Validator validator) {
        Map<String, Property> ret = new HashMap<>();
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User user = getUserData(mKeyDatabase, record);
            if (user != null) {
                for (String n : names) {
                    User.PropertyEntry property_entry = user.valueReferences.get(n);
                    if (property_entry != null && property_entry.id != null) {
                        synchronized (mValues) {
                            String encoded_property = mValues.get(property_entry.id);
                            if (encoded_property != null) {
                                Property p = getPropertyData(mKeyDatabase, encoded_property, record.keyName);
                                if (p != null) {
                                    ret.put(n, p);
                                }
                            }
                        }
                    }
                }
            }
        }
        return ret;
    }

    @Override
    public ErrorCode setUserProperties(Map<String, Property> properties, Validator validator) {
        UserRecord record = getUserRecord(validator);
        if (record != null) {
            User user = getUserData(mKeyDatabase, record);
            if (user != null) {
                for (Map.Entry<String, Property> entry : properties.entrySet()) {
                    // TODO: 26/6/21 Añadir las propiedades detached
                    if (!entry.getValue().detached) {
                        User.PropertyEntry property_entry = user.valueReferences.get(entry.getKey());
                        if (property_entry != null && property_entry.id != null) {
                            synchronized (mValues) {
                                String encoded_property = mKeyDatabase.encryptObjectToBase64(entry.getValue(), record.keyName, mGson);
                                mValues.put(property_entry.id, encoded_property);
                            }
                        }
                    }
                }
            }
        }
        return ErrorCode.SUCCEDED;
    }

    @Override
    public Application getApplication(Validator validator) {
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

    private UserRecord getUserRecord(Validator validator) {
        if (validator == null)
            return null;
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
                    String key_name = mKeyDatabase.getRandomPublicKeyName(KeyDatabase.Encoding.ASYMMETRIC);
                    {
                        User user = new User();
                        user.id = UUID.randomUUID();
                        {
                            Long id = createValueEntry();
                            setValue(id, new Property("admin"), key_name);
                            user.valueReferences.put(User.NAME_FIELD, new User.PropertyEntry(id));
                        }
                        user.type = User.Type.ADMIN;
                        userData = mKeyDatabase.encryptObjectToBase64(user, key_name, mGson);
                    }
                    String sha256hex = DigestUtils.sha256Hex(validator.password);

                    UserRecord record = new UserRecord();
                    record.userData = userData;
                    record.passwordHash = sha256hex;
                    record.keyName = key_name;
                    mUserList.add(record);

                    return generateTokenForUser(validator);
               }
            } else {
                UserRecord user_record = getUserRecord(validator);
                if (user_record != null) {
                    Token.UserData data = new Token.UserData();
                    User user = mKeyDatabase.decryptBase64ToObject(user_record.userData, User.class, user_record.keyName, mGson);
                    //data.values = user.values;
                    data.date = TimeUtils.now();
                    data.applicationCode = null;
                    data.applicationName = null;

                    try {
                        Token ret = new Token();
                        ret.serverPublicKeyName = user_record.keyName;
                        ret.userData = mKeyDatabase.encryptObjectToBase64(data, user_record.keyName, mGson);
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
        /*
        User user = getUser(validator);
        if (user != null) {
            user.publicKey = publicKey;
            return updateUser(user, validator);
        } else

         */
            return ErrorCode.INVALID_USER;
    }

}
