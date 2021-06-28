package com.servers.interop;

public enum ErrorCode {
    SUCCEDED(0),
    INVALID_PARAMS(1),
    INVALID_USER(2),
    OPERATION_NOT_ALLOWED(3),
    NON_ATTENDED(4),
    USER_FIELD_ALREADY_EXISTS(5),
    INVALID_VALIDATOR(6),
    INVALID_STATE(7),
    NO_HUMAN_VERIFICATION(100);

    private int value;

    ErrorCode(int value) {
        this.value = value;
    }
}
