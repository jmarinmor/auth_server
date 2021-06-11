package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.SetAdminPrivateKey;

public class SetAdminPrivateKeyRequest {
    public static class Response {
        public ErrorCode errorCode;
    }

    public SetAdminPrivateKey content;
}
