package com.auth.interop.requests;

import com.auth.interop.User;
import com.auth.interop.Validator;

import java.util.UUID;

public class VerifyUser extends Validator {
    public static class Response {
        public UUID id;

        public Response(UUID id) {
            this.id = id;
        }
    }
}
