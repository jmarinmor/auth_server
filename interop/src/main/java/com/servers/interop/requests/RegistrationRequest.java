package com.servers.interop.requests;

import com.servers.interop.ErrorCode;
import com.servers.interop.Inquiry;
import com.servers.interop.Token;

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
