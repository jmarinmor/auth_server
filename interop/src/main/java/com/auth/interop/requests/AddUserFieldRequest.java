package com.auth.interop.requests;

import com.auth.interop.contents.AddUserField;
import com.auth.interop.ErrorCode;

public class AddUserFieldRequest {
    public static class Response {

        public ErrorCode errorCode;
    }

    public AddUserField content;
}
