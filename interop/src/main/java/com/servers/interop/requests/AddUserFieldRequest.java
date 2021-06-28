package com.servers.interop.requests;

import com.servers.interop.contents.AlterUserField;
import com.servers.interop.ErrorCode;
import com.servers.interop.contents.EncryptedContent;

public class AddUserFieldRequest extends EncryptedContent<AlterUserField> {
    public static class Response {

        public ErrorCode errorCode;
    }
}
