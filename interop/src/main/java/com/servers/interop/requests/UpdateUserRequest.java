package com.servers.interop.requests;

import com.servers.interop.ErrorCode;
import com.servers.interop.User;
import com.servers.interop.Validator;

public class UpdateUserRequest extends Validator {
    public static class Response {
        public ErrorCode errorCode;
    }

    public User user;
}
