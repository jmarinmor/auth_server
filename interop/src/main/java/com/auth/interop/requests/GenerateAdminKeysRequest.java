package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;
import com.auth.interop.contents.GenerateKeyPair;

public class GenerateAdminKeysRequest extends EncryptedContent<GenerateKeyPair> {
    public static class Response {
        public static class Content {
            public String publicKey;
            public String privateKey;

            public Content(String publicKey, String privateKey) {
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            }
        }

        public ErrorCode errorCode;
        public Content response;
    }
}
