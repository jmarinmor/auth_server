package com.auth.interop.requests;

import com.auth.interop.Inquiry;

public class VerifyHumanRequest {
    public enum Reason {
        REGISTRY
    }

    public static class Response {
        public Inquiry inquiry;
        public String captchaImage;
    }

    public Reason reason;
}
