package com.auth.interop.requests;

import com.auth.interop.contents.AlterUserField;
import com.auth.interop.ErrorCode;
import com.auth.interop.contents.EncryptedContent;

public class AddUserFieldRequest extends EncryptedContent<AlterUserField> {
    public static class Response {

        public ErrorCode errorCode;
    }
}
