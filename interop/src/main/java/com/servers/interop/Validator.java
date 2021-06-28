package com.servers.interop;

public class Validator {
    public String applicationCode;
    public String mail;
    public String phone;
    public String password;
    public Token token;
    public byte[] publicKey;

    public static Validator fromPassword(String password) {
        Validator ret = new Validator();
        ret.password = password;
        return ret;
    }
}
