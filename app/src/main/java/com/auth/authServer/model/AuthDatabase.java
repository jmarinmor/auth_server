package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.contents.*;

import java.security.KeyPair;
import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {
    ErrorCode setAlive(SetAlive value);
    ErrorCode panic();

    // Every user has every field specified by the server administrator
    ErrorCode addUserPropertyField(EncryptedContent<AddUserField> content);
    UserFields getUserPropertyFields();

    ErrorCode registerInquiry(Inquiry inquiry);
    ErrorCode sendInquiry(Inquiry.Reason reason, Validator validator);

    UUID verifyUser(Validator validator);
    ErrorCode updateUser(User user, KeyDatabase keyDatabase, Validator validator);
    ErrorCode updateUserValidator(String newPassword, Validator validator, Validator newValidator);
    User getUser(KeyDatabase keyDatabase, Validator validator);

    ErrorCode grantApplicationForUser(Validator validator, String appCode);
    Token generateTokenForUser(KeyDatabase keyDatabase, Validator validator);

    default ErrorCode setUserPublicKey(String publicKey, KeyDatabase keyDatabase, Validator validator) {
        User user = getUser(keyDatabase, validator);
        if (user != null) {
            user.publicKey = publicKey;
            return updateUser(user, keyDatabase, validator);
        } else
            return ErrorCode.INVALID_USER;
    }

}
