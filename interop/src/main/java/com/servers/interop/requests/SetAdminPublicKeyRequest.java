package com.servers.interop.requests;

import com.servers.interop.ErrorCode;
import com.servers.interop.contents.AdminPublicKeyContainer;

public class SetAdminPublicKeyRequest extends AdminPublicKeyContainer {
    public static class Response {
        public ErrorCode errorCode;
    }
}
