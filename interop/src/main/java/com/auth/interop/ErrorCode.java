package com.auth.interop;

public enum ErrorCode {
    SUCCEDED(0),
    INVALID_PARAMS(1),
    INVALID_USER(2),
    NO_HUMAN_VERIFICATION(100);

    private int value;

    ErrorCode(int value) {
        this.value = value;
    }
}
