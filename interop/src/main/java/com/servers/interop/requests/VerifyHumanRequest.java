package com.servers.interop.requests;

import com.jcore.servers.Inquiry;

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
