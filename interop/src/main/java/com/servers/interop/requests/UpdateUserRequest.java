package com.servers.interop.requests;

import com.jcore.servers.User;
import com.jcore.servers.Validator;
import com.servers.interop.ErrorCode;

public class UpdateUserRequest extends Validator {
    public static class Response {
        public ErrorCode errorCode;
    }

    public User user;
}
