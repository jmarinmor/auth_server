package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.contents.*;

import java.security.KeyPair;
import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {
    boolean USE_DEBUG_INFO = true;

    // Local functions
    ErrorCode panic();

    // Admin functions
    AdminCommand.Response executeAdminCommand(String command);
    UserFields getUserPropertyFields();

    Inquiry.Response registerInquiry(Inquiry inquiry, Inquiry.Action action, Inquiry.ActionParams params);
    Inquiry.Response verifyInquiry(Inquiry inquiry, Inquiry.ActionParams params);

    ErrorCode updateUser(User.PublicData user, Validator validator);
    ErrorCode updateUserValidator(Validator validator, Validator newValidator);
    ErrorCode setUserPublicKey(String publicKey, Validator validator);
    User.PublicData getUser(Validator validator);
    Token generateTokenForUser(Validator validator);
}
