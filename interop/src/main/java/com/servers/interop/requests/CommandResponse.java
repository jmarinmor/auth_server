package com.servers.interop.requests;

import com.servers.interop.ErrorCode;

public class CommandResponse<T> {
    public ErrorCode errorCode;
    public String errorString;
    public T response;

    public CommandResponse() {
    }

    public CommandResponse(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public CommandResponse(ErrorCode errorCode, String errorString, T response) {
        this.errorCode = errorCode;
        this.errorString = errorString;
        this.response = response;
    }
}
