package com.auth.authServer.model;

import com.servers.interop.*;
import com.servers.interop.Application;
import com.servers.interop.commands.GetUsersProgression;
import com.servers.interop.commands.SetPublicKey;

import java.util.Map;
import java.util.Set;

public interface AuthDatabase extends AutoCloseable {
    boolean USE_DEBUG_INFO = true;

    // Local functions
    ErrorCode panic();

    // Admin functions
    ErrorCode setAdminPublicKey(CommandRequest<SetPublicKey> command);
    Double getUsersProgression(CommandRequest<GetUsersProgression> command);
    Set<String> getUserPropertyFields();

    Inquiry.Response registerInquiry(Inquiry inquiry, Inquiry.Action action, Inquiry.ActionParams params);
    Inquiry.Response verifyInquiry(Inquiry inquiry, Inquiry.ActionParams params);

    ErrorCode updateUser(User user, Validator validator);
    ErrorCode updateUserValidator(Validator validator, Validator newValidator);
    ErrorCode setUserPublicKey(String publicKey, Validator validator);
    User getUser(Validator validator);
    Set<String> getUserFields(Validator validator);
    Map<String, Property> getUserProperties(Set<String> names, Validator validator);
    ErrorCode setUserProperties(Map<String, Property> properties, Validator validator);
    Application getApplication(Validator validator);
    Token generateTokenForUser(Validator validator);

    /*
    default AdminCommand.Response executeAdminCommand(String command) {
        CommandRequest cmd = new CommandRequest(command);
        return executeAdminCommand(cmd);
    }

     */
}
