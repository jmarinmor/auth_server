package com.auth.authServer.model.implementations;

import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.Inquiry;
import com.auth.interop.User;
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
        public String protectedData;
        public Map<String, String> resources;
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

    protected static boolean performUpdateUserRecord(KeyDatabase database, User.ProtectedData user, UserRecord record) {
        String userData = database.encrypt(user, record.keyName);
        record.protectedData = userData;
        return true;
    }

    protected static User.ProtectedData getUserProtectedData(KeyDatabase database, UserRecord record) {
        if (record != null) {
            User.ProtectedData user = database.decrypt(record.protectedData, User.ProtectedData.class, record.keyName);
            return user;
        }
        return null;
    }

    protected boolean performCheckUserRecordField(AlterUserField cmd, UserRecord record) {
        User.ProtectedData user = getUserProtectedData(mKeyDatabase, record);
        if (user != null) {
            String value = user.values.get(cmd.name);
            if (!cmd.properties.checkValue(value)) {
                if (user.values != null)
                    user.values.put(cmd.name, "");
                return performUpdateUserRecord(mKeyDatabase, user, record);
            }
        }
        return false;
    }

    protected void performDeleteUserRecordField(AlterUserField cmd, UserRecord record) {
        User.ProtectedData user = getUserProtectedData(mKeyDatabase, record);
        if (user != null) {
            if (user.values != null)
                user.values.remove(cmd.name);
            if (user.appFields != null)
                user.appFields.remove(cmd.name);
            performUpdateUserRecord(mKeyDatabase, user, record);
        }
    }

    protected void performUpdateUserRecordField(AlterUserField cmd, UserRecord record) {
        User.ProtectedData user = getUserProtectedData(mKeyDatabase, record);
        if (user.values != null)
            user.values.put(cmd.name, "");
        performUpdateUserRecord(mKeyDatabase, user, record);
    }

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

    protected ErrorCode performUpdateUserRecord(User.PublicData user, UserRecord record) {
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
            if (!cmd.properties.isValid()) {
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
