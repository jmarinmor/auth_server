package com.auth.interop.requests;

import com.auth.interop.ErrorCode;

public class RequestResponse <T> {
    public ErrorCode errorCode;
    public T response;
}
