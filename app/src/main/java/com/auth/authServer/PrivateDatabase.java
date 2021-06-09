package com.auth.authServer;

import com.auth.interop.Captcha;
import com.auth.interop.Inquiry;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

public interface PrivateDatabase extends AutoCloseable {
    class Validator {
        public String applicationCode;
        public String mail;
        public String phone;
        public String password;
        public Inquiry inquiry;
        public byte[] publicKey;
    }

    class AddField {
        public class Message {
            public String valueName;
        }
        public byte[] encodedMessage;
    }

    class Token {
        public static class User {
            public String applicationCode;
            public String applicationName;
            public Map<String, String> values;
        }
        public String serverPublicKeyName;
        byte[] userData;

        public User decypherUser(byte[] serverPublicKey) {
            return null;
        }
    }

    class User {
        String NAME_FIELD = "name";
        String VOID_STRING = "";

        public UUID id;
        public Map<String, String> values;

        public String getNameField() {
            return getUserField(NAME_FIELD);
        }

        public String getUserField(String field) {
            if (field == null || values == null)
                return VOID_STRING;
            String ret = values.get(field);
            if (ret == null)
                return VOID_STRING;
            return ret;
        }

    }

    class UserCompleteProfile extends User {
        public Set<String> appFields;
        public String appCode;
        public byte[] appPublicKey;
    }

    class PublicKey {
        public String name;
        public byte[] key;
        public boolean isAuth;
    }

    class ApplicationProfile {
        public class Message {
            public User user;
        }
        public byte[] message;
    }

    void setServerMainPublicKey(byte[] ownerPublicKey);
    PublicKey getServerPublicKey(String name);
    void panic();

    void addUserField(AddField field);
    Set<String> getUserFields();

    void registerHumanVerificationInquiry(Inquiry inquiry);
    boolean sendValidationInquiry(Validator validator);
    void updateUser(User user, Validator validator);
    User getUser(Validator validator);

    void registerUserInApplication(String appCode, Validator validator);
    ApplicationProfile getApplicationProfileForUser(UUID userId, Validator validator);
    void login(Validator validator);
    Token getLoginTokenForApplication(String applicationCodeId, Validator validator);
}
