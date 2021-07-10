package com.servers.interop.requests;

import com.jcore.servers.EncryptedRequest;
import com.servers.interop.commands.Panic;

public class PanicCommandRequest extends EncryptedRequest<Panic> {
    public String serviceCode;
}
