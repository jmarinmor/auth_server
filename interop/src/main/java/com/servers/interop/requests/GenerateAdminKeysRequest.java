package com.servers.interop.requests;

import com.servers.interop.ErrorCode;
import com.servers.interop.contents.EncryptedContent;
import com.servers.interop.contents.GenerateKeyPair;

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
