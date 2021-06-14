package com.auth.authServer.model.implementations;

import com.auth.interop.*;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.contents.*;
import com.auth.interop.requests.RegistrationRequest;

import java.security.KeyPair;
import java.util.UUID;

public class AuthDatabaseImplementationRAM implements AuthDatabase {

    private static RegistrationRequest.PreferedRagistrationMode getPreferedRegistrationMode(RegistrationRequest registrationRequest) {
        if (registrationRequest.preferedRagistrationMode != null) {
            return registrationRequest.preferedRagistrationMode;
        } else {
            if (registrationRequest.phone != null)
                return RegistrationRequest.PreferedRagistrationMode.PHONE;
            if (registrationRequest.mail != null)
                return RegistrationRequest.PreferedRagistrationMode.MAIL;
        }
        return RegistrationRequest.PreferedRagistrationMode.NOT_AVAILABLE;
    }

    @Override
    public ErrorCode setAlive(SetAlive value) {
        return null;
    }

    @Override
    public ErrorCode panic() {
        return null;
    }

    @Override
    public ErrorCode addUserPropertyField(EncryptedContent<AddUserField> content) {
        return null;
    }

    @Override
    public UserFields getUserPropertyFields() {
        return null;
    }

    @Override
    public ErrorCode registerInquiry(Inquiry inquiry) {
        return null;
    }

    @Override
    public ErrorCode sendInquiry(Inquiry.Reason reason, Validator validator) {
        return null;
    }

    @Override
    public UUID verifyUser(Validator validator) {
        return null;
    }

    @Override
    public ErrorCode updateUser(User user, Validator validator) {
        return null;
    }

    @Override
    public User getUser(Validator validator) {
        return null;
    }

    @Override
    public ErrorCode grantApplicationForUser(Validator validator, String appCode) {
        return null;
    }

    @Override
    public Token generateTokenForUser(Validator validator) {
        return null;
    }

    @Override
    public void close() throws Exception {

    }
}
