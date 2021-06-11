package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.contents.GenerateAdminKeys;

public class GenerateAdminKeysRequest {
    public static class Response {
        public static class Content {
            public String key;

            public Content(String key) {
                this.key = key;
            }
        }

        public ErrorCode errorCode;
        public Content response;
    }

    public GenerateAdminKeys content;
}
