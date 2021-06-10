package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.Inquiry;
import com.auth.interop.Token;

public class RegistrationRequest {
    public enum PreferedRagistrationMode {
        NOT_AVAILABLE,
        MAIL,
        PHONE
    }

    public static class Response {
        public ErrorCode errorCode;
        public Token response;
    }

    public Inquiry inquiry;
    public String name;
    public String phone;
    public String mail;
    public String password;
    public PreferedRagistrationMode preferedRagistrationMode;
}
