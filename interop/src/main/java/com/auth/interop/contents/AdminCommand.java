package com.auth.interop.contents;

import java.util.Date;

public class AdminCommand {
    public enum Type {
        SET_PUBLIC_KEY,
        PANIC,
        ADD_USER_FIELD
    }

    public Date date;
    public Type type;
    public String publicKey;
    public String userFieldName;

    public static AdminCommand newSetPublicKey(String base64PublicKey) {
        AdminCommand ret = new AdminCommand();
        ret.date = new Date();
        ret.type = Type.SET_PUBLIC_KEY;
        ret.publicKey = base64PublicKey;

        return ret;
    }

    public static AdminCommand newAddUserField(String field) {
        AdminCommand ret = new AdminCommand();
        ret.date = new Date();
        ret.type = Type.ADD_USER_FIELD;
        ret.userFieldName = field;

        return ret;
    }
}
