package com.servers.interop.requests;

import com.servers.interop.Validator;

import java.util.UUID;

public class VerifyUser extends Validator {
    public static class Response {
        public UUID id;

        public Response(UUID id) {
            this.id = id;
        }
    }
}
