package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.SetPanicPublicKey;

public class SetPanicPublicKeyRequest extends EncryptedContent<SetPanicPublicKey> {
    public static class Response {
        public ErrorCode errorCode;
    }
}
