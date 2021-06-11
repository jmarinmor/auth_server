package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.SetAdminPrivateKey;

public class SetAdminPrivateKeyRequest extends EncryptedContent<SetAdminPrivateKey> {
    public static class Response {
        public ErrorCode errorCode;
    }
}
