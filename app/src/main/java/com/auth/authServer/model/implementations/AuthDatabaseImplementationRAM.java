package com.auth.authServer.model.implementations;

import com.auth.interop.*;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.contents.AddUserField;
import com.auth.interop.contents.GenerateAdminKeys;
import com.auth.interop.contents.SetAdminPrivateKey;
import com.auth.interop.contents.SetPanicPublicKey;
import com.auth.interop.requests.RegistrationRequest;

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
    public ErrorCode setPanicPublicKeys(SetPanicPublicKey value) {
        return null;
    }

    @Override
    public ErrorCode panic() {
        return null;
    }

    @Override
    public ErrorCode setAdminPrivateKey(SetAdminPrivateKey value) {
        return null;
    }

    @Override
    public byte[] generateAdminKeys(GenerateAdminKeys value) {
        return new byte[0];
    }

    @Override
    public <T> T decipherByAdminKey(byte[] data, Class<T> aClass) {
        return null;
    }

    @Override
    public ErrorCode addUserField(AddUserField value) {
        return null;
    }

    @Override
    public UserFields getUserFields() {
        return null;
    }

    @Override
    public NamedPublicKey getServerPublicKey(String name) {
        return null;
    }

    @Override
    public ErrorCode registerHumanVerificationInquiry(Inquiry inquiry) {
        return null;
    }

    @Override
    public ErrorCode sendValidationInquiry(Validator validator) {
        return null;
    }

    @Override
    public ErrorCode verifyUser(Validator validator) {
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
    public ErrorCode registerUserInApplication(String appCode, Validator validator) {
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
