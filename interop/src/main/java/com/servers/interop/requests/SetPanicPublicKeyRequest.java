package com.servers.interop.requests;

import com.servers.interop.ErrorCode;
import com.servers.interop.contents.EncryptedContent;
import com.servers.interop.contents.PanicPublicKey;

public class SetPanicPublicKeyRequest extends EncryptedContent<PanicPublicKey> {
    public static class Response {
        public ErrorCode errorCode;
    }
}
