package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.SetPanicPublicKey;

public class SetPanicPublicKeyRequest {
    public static class Response {
        public ErrorCode errorCode;
    }

    // Base 64 key
    public SetPanicPublicKey content;
}
