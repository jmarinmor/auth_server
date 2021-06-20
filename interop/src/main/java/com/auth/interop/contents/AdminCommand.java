package com.auth.interop.contents;

import com.auth.interop.ErrorCode;
import com.auth.interop.UserFields;

import java.util.Date;

public class AdminCommand {
    public enum Type {
        SET_PUBLIC_KEY,
        PANIC,
        ALTER_USER_FIELD,
        GET_USERS_PROGRESSION
    }

    public static class Response {
        public ErrorCode errorCode;
        public double progression;

        public Response() {
        }

        public Response(ErrorCode errorCode) {
            this.errorCode = errorCode;
        }
    }

    public Date date;
    public Type type;
    public String publicKey;
    public AlterUserField alterUserField;

    public static AdminCommand newSetPublicKey(String base64PublicKey) {
        AdminCommand ret = new AdminCommand();
        ret.date = new Date();
        ret.type = Type.SET_PUBLIC_KEY;
        ret.publicKey = base64PublicKey;

        return ret;
    }

    public static AdminCommand newAddUserField(String name, UserFields.FieldProperties properties) {
        AdminCommand ret = new AdminCommand();
        ret.date = new Date();
        ret.type = Type.ALTER_USER_FIELD;
        ret.alterUserField = new AlterUserField(name, properties);

        return ret;
    }
}
