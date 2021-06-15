package com.auth.interop.requests;

import com.auth.interop.ErrorCode;
import com.auth.interop.User;
import com.auth.interop.Validator;

public class UpdateUserRequest extends Validator {
    public static class Response {
        public ErrorCode errorCode;
    }

    public User.PublicData user;
}
