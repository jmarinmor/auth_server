package com.auth.authServer.model.implementations;

import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.*;
import com.auth.interop.contents.AdminCommand;
import com.auth.interop.contents.AlterUserField;
import com.auth.interop.requests.CommandRequest;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public abstract class AuthDatabaseImplementation implements AuthDatabase {


    protected static class UserRecord {
        public String userData;
        public String applicationData;
        public String privateData;
        public String concessionsData;

        public String userPublicKey;
        public String keyName;

        public String phoneHash;
        public String mailHash;
        public String passwordHash;
    }


    protected static class InquiryRecord {
        public String key;
        public String value;
        public Inquiry.Action action;
        public Inquiry.ActionParams params;
    }

    protected static Gson mGson = new Gson();
    protected KeyDatabase mKeyDatabase;

    protected static boolean performUpdateUserRecord(KeyDatabase database, User user, UserRecord record) {
        String userData = database.encryptObjectToBase64(user, record.keyName, mGson);
        record.userData = userData;
        return true;
    }

    protected static User getUserData(KeyDatabase database, UserRecord record) {
        if (record != null) {
            User data = database.decryptBase64ToObject(record.userData, User.class, record.keyName, mGson);
            return data;
        }
        return null;
    }

    protected static Application getApplicationData(KeyDatabase database, UserRecord record) {
        if (record != null) {
            Application data = database.decryptBase64ToObject(record.applicationData, Application.class, record.keyName, mGson);
            return data;
        }
        return null;
    }

    protected static Concessions getConcessionsData(KeyDatabase database, UserRecord record) {
        if (record != null) {
            Concessions data = database.decryptBase64ToObject(record.concessionsData, Concessions.class, record.keyName, mGson);
            return data;
        }
        return null;
    }

    protected static Property getPropertyData(KeyDatabase database, String encodedProperty, String keyName) {
        if (encodedProperty != null && keyName != null && database != null) {
            Property data = database.decryptBase64ToObject(encodedProperty, Property.class, keyName, mGson);
            return data;
        }
        return null;
    }

    protected boolean performCheckUserRecordField(String fieldName, UserRecord record) {
        User user = getUserData(mKeyDatabase, record);
        if (user != null) {
            if (user.valueReferences == null)
                user.valueReferences = new HashMap<>();
            User.PropertyEntry property = user.valueReferences.get(fieldName);
            if (property == null) {
                user.valueReferences.put(fieldName, null);
                return performUpdateUserRecord(mKeyDatabase, user, record);
            }
        }
        return false;
    }

    protected void performDeleteUserRecordField(String fieldName, UserRecord record) {
        User user = getUserData(mKeyDatabase, record);
        if (user != null) {
            if (user.valueReferences != null)
                user.valueReferences.remove(fieldName);
            performUpdateUserRecord(mKeyDatabase, user, record);
        }
    }

    protected void performUpdateUserRecordField(String fieldName, UserRecord record) {
        User user = getUserData(mKeyDatabase, record);
        if (user.valueReferences == null)
            user.valueReferences = new HashMap<>();
        user.valueReferences.put(fieldName, null);
        performUpdateUserRecord(mKeyDatabase, user, record);
    }

    protected ErrorCode convert(User from, User to, String keyName) {

        /*
        Map<String, Long> values = to.valueReferences == null ? new HashMap<>() : new HashMap<>(to.valueReferences);
        if (from.values != null) {
            for (Map.Entry<String, Property> entry : from.values.entrySet()) {
                String field_name = entry.getKey().toLowerCase();
                Long id = to.valueReferences.get(field_name);
                if (id == null) {
                    id = createValueEntry();
                }
                setValue(id, entry.getValue(), keyName);
                values.put(entry.getKey(), id);
            }
        }
        to.valueReferences = values;
         */

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
                //to.appCode = sha256hex;
            }
        }

        return ErrorCode.SUCCEDED;
    }



    /*
    protected static ErrorCode convert(User.PublicData from, User.ProtectedData to) {
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
*/
    protected ErrorCode performUpdateUserRecord(User user, UserRecord record) {
        User stored_user = mKeyDatabase.decryptBase64ToObject(record.userData, User.class, record.keyName, mGson);
        if (!stored_user.id.equals(user.id))
            return ErrorCode.INVALID_USER;

        ErrorCode r = convert(user, stored_user, record.keyName);
        if (r != ErrorCode.SUCCEDED)
            return r;

        String userData = mKeyDatabase.encryptObjectToBase64(stored_user, record.keyName, mGson);
        record.userData = userData;

        return ErrorCode.SUCCEDED;
    }

    protected abstract void setValue(Long id, Property value, String keyName);
    abstract protected Long createValueEntry();
    abstract protected double getUpdateUsersProgression();
    abstract protected boolean containsUserField(String name);
    abstract protected void performAlterFieldInAllUsers(AlterUserField cmd, boolean add, boolean delete, boolean update);

    protected ErrorCode performAlterUserField(AlterUserField cmd) {
        if (cmd == null || cmd.name == null || cmd.properties == null)
            return ErrorCode.INVALID_PARAMS;
        ErrorCode ret = ErrorCode.SUCCEDED;
        boolean remove = false, add = false, update = false;

        final boolean exists = containsUserField(cmd.name);
        boolean perform = false;

        if (cmd.removeField) {
            if (exists) {
                remove = true;
                perform = true;
            } else {
                ret = ErrorCode.INVALID_PARAMS;
            }
        } else {
            if (cmd.properties == null || cmd.properties.size() == 0) {
                ret = ErrorCode.INVALID_PARAMS;
            } else {
                if (exists) {
                    if (cmd.overrideExisting) {
                        perform = true;
                        update = true;
                    } else {
                        ret = ErrorCode.USER_FIELD_ALREADY_EXISTS;
                    }
                } else {
                    add = true;
                    perform = true;
                }
            }
        }

        if (perform)
            performAlterFieldInAllUsers(cmd, add, remove, update);
        return ret;
    }

    @Override
    public AdminCommand.Response executeAdminCommand(CommandRequest command) {
        if (mKeyDatabase == null)
            return new AdminCommand.Response(ErrorCode.INVALID_STATE);
        ErrorCode e = mKeyDatabase.executeAdminCommand(command);
        if (e != ErrorCode.SUCCEDED && e != ErrorCode.NON_ATTENDED)
            return new AdminCommand.Response(e);

        if (e == ErrorCode.NON_ATTENDED) {
            AdminCommand cmd = mKeyDatabase.decryptAdminCommand(command);
            if (cmd != null) {
                switch (cmd.type) {
                    case ALTER_USER_FIELD: {
                        e = performAlterUserField(cmd.alterUserField);
                        return new AdminCommand.Response(e);
                    }
                    case GET_USERS_PROGRESSION: {
                        AdminCommand.Response ret = new AdminCommand.Response(ErrorCode.SUCCEDED);
                        ret.progression = getUpdateUsersProgression();
                        return ret;
                    }
                }
            }
        }
        return new AdminCommand.Response(ErrorCode.SUCCEDED);
    }
}
