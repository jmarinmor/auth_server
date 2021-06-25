package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.Application;
import com.auth.interop.contents.*;
import com.auth.interop.requests.CommandRequest;

public interface AuthDatabase extends AutoCloseable {
    boolean USE_DEBUG_INFO = true;

    // Local functions
    ErrorCode panic();

    // Admin functions
    AdminCommand.Response executeAdminCommand(CommandRequest<AdminCommand> command);
    UserFields getUserPropertyFields();

    Inquiry.Response registerInquiry(Inquiry inquiry, Inquiry.Action action, Inquiry.ActionParams params);
    Inquiry.Response verifyInquiry(Inquiry inquiry, Inquiry.ActionParams params);

    ErrorCode updateUser(User user, Validator validator);
    ErrorCode updateUserValidator(Validator validator, Validator newValidator);
    ErrorCode setUserPublicKey(String publicKey, Validator validator);
    User getUser(Validator validator);
    Application getApplication(Validator validator);
    Token generateTokenForUser(Validator validator);

    default AdminCommand.Response executeAdminCommand(String command) {
        CommandRequest cmd = new CommandRequest(command);
        return executeAdminCommand(cmd);
    }
}
