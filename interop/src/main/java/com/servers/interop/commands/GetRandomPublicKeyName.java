package com.servers.interop.commands;

import java.util.Date;

public class GetRandomPublicKeyName {
    public enum Encoding {
        ASYMMETRIC,
        SYMMETRIC
    }

    public Date date;
    public Encoding encoding;
}
