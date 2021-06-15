package com.auth.interop;

public enum ErrorCode {
    SUCCEDED(0),
    INVALID_PARAMS(1),
    INVALID_USER(2),
    OPERATION_NOT_ALLOWED(3),
    NON_ATTENDED(4),
    NO_HUMAN_VERIFICATION(100);

    private int value;

    ErrorCode(int value) {
        this.value = value;
    }
}
