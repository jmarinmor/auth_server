package com.auth.interop;

import java.util.Date;
import java.util.UUID;

public class User {
    public static class Data {
        public String app;
        public String name;
        public String mail;
        public String mail_password;
        public String phone;
        public String phone_password;
        public Date phone_valid_date;
    }

    public static class Instance extends Data {
        public Long id;
        public UUID gid;

    }

    public static class Record extends Instance {
        public String mail_hash;
        public String phone_hash;
        public String password_hash;
        public String phone_verify_code;
        public String email_verify_code;

    }

}
