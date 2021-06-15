package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.AdminPublicKeyContainer;

public class SetAdminPublicKeyRequest extends AdminPublicKeyContainer {
    public static class Response {
        public ErrorCode errorCode;
    }
}
