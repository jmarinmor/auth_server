package com.auth.interop.requests;

import com.auth.interop.contents.AddUserField;
import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;

public class AddUserFieldRequest extends EncryptedContent<AddUserField> {
    public static class Response {

        public ErrorCode errorCode;
    }
}