package com.servers.interop.requests;

import com.servers.interop.commands.Panic;

public class PanicCommandRequest extends CommandRequest<Panic> {
    public String serviceCode;
}
