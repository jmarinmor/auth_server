package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.contents.AddUserField;
import com.auth.interop.contents.GenerateAdminKeys;
import com.auth.interop.contents.SetAdminPrivateKey;
import com.auth.interop.contents.SetPanicPublicKey;

public interface AuthDatabase extends AutoCloseable {

    // Panic key is used to cipher data in case of panic
    ErrorCode setPanicPublicKeys(SetPanicPublicKey value);
    ErrorCode panic();

    // Admin private key is used for decipher incomming messages in order to check they are valid
    ErrorCode setAdminPrivateKey(SetAdminPrivateKey value);
    byte[] generateAdminKeys(GenerateAdminKeys value);
    <T> T decipherByAdminKey(byte[] data, Class<T> aClass);
    // Every user has every field specified by the server administrator
    ErrorCode addUserField(AddUserField value);
    UserFields getUserFields();

    NamedPublicKey getServerPublicKey(String name);

    ErrorCode registerHumanVerificationInquiry(Inquiry inquiry);
    ErrorCode sendValidationInquiry(Validator validator);
    ErrorCode verifyUser(Validator validator);
    ErrorCode updateUser(User user, Validator validator);
    User getUser(Validator validator);

    ErrorCode registerUserInApplication(String appCode, Validator validator);
    Token generateTokenForUser(Validator validator);
}
