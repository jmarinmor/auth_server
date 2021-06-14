package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.PanicPublicKey;

public class SetPanicPublicKeyRequest extends EncryptedContent<PanicPublicKey> {
    public static class Response {
        public ErrorCode errorCode;
    }
}
