package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.AdminPrivateKey;

public class SetAdminPrivateKeyRequest extends EncryptedContent<AdminPrivateKey> {
    public static class Response {
        public ErrorCode errorCode;
    }
}
