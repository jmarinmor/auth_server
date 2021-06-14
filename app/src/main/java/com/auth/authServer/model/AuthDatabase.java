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
    ErrorCode updateUser(User user, Validator validator);
    User getUser(Validator validator);

    ErrorCode grantApplicationForUser(Validator validator, String appCode);
    Token generateTokenForUser(Validator validator);
}
