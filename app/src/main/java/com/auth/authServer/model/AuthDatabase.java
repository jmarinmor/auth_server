package com.auth.authServer.model;

import com.auth.interop.*;
import com.auth.interop.contents.*;

import java.security.KeyPair;
import java.util.UUID;

public interface AuthDatabase extends AutoCloseable {

    // ** Panic key is used to cipher data in case of panic
    /**
     * This functions sets the panic public key. In the case of panic, all the internal kays will
     * be ciphered by this public key, so the only way to decipher it again is to call the setAlive
     * function giving the private key to restore them.
     * @param value
     * @return
     */
    ErrorCode setPanicPublicKeys(EncryptedContent<SetPanicPublicKey> value);
    ErrorCode setAlive(SetAlive value);
    ErrorCode panic();

    // Admin private key is used for decipher incomming messages in order to check they are valid
    ErrorCode setAdminPublicKey(EncryptedContent<SetAdminPrivateKey> value);
    // Every user has every field specified by the server administrator
    ErrorCode addUserField(EncryptedContent<AddUserField> content);
    UserFields getUserFields();

    KeyPair generateKeyPair(EncryptedContent<GenerateKeyPair> value);
    NamedPublicKey getServerPublicKey(String name);

    ErrorCode registerInquiry(Inquiry inquiry);
    ErrorCode sendInquiry(Inquiry.Reason reason, Validator validator);

    UUID verifyUser(Validator validator);
    ErrorCode updateUser(User user, Validator validator);
    User getUser(Validator validator);

    ErrorCode grantApplicationForUser(Validator validator, String appCode);
    Token generateTokenForUser(Validator validator);
}
