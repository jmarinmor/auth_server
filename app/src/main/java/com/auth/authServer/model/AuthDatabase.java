package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.contents.*;

import java.security.KeyPair;
import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {
    boolean USE_DEBUG_INFO = true;

    // Admin functions
    ErrorCode executeAdminCommand(String command, KeyDatabase keyDatabase);
    ErrorCode panic();
    UserFields getUserPropertyFields();

    Inquiry.Response registerInquiry(Inquiry inquiry, Inquiry.Action action, Inquiry.ActionParams params, KeyDatabase keyDatabase);
    Inquiry.Response verifyInquiry(Inquiry inquiry, Inquiry.ActionParams params, KeyDatabase keyDatabase);

    ErrorCode updateUser(User.PublicData user, KeyDatabase keyDatabase, Validator validator);
    ErrorCode updateUserValidator(Validator validator, Validator newValidator);
    ErrorCode setUserPublicKey(String publicKey, KeyDatabase keyDatabase, Validator validator);
    User.PublicData getUser(KeyDatabase keyDatabase, Validator validator);

    ErrorCode grantApplicationForUser(Validator validator, String appCode);
    Token generateTokenForUser(KeyDatabase keyDatabase, Validator validator);
}
