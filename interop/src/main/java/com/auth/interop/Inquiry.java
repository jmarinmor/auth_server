package com.auth.interop;

import org.apache.commons.lang3.StringUtils;

import java.util.Random;
import java.util.UUID;

public class Inquiry {
    public enum Reason {
        HUMAN_VERIFICATION(1),
        REGISTER_VALIDATION(2),
        UPDATE_USER(3),
        GRANT_APPLICATION_FOR_USER(4);

        private int type;
        Reason(int type) {this.type = type;}
    }

    private static final Random mRandom = new Random();

    public Reason reason;
    public String inquiry;
    public String desiredResult;

    public Inquiry() {
    }

    public Inquiry(String inquiry, String desiredResult) {
        this.inquiry = inquiry;
        this.desiredResult = desiredResult;
    }

    public static Inquiry generateNewInquiry() {
        Inquiry ret = new Inquiry();
        ret.inquiry = UUID.randomUUID().toString();
        ret.desiredResult = UUID.randomUUID().toString();
        return ret;
    }

    public Inquiry getInquiry() {
        Inquiry ret = new Inquiry();
        ret.inquiry = inquiry;
        ret.desiredResult = desiredResult;
        return ret;
    }

    public static Random getRandom() {
        return mRandom;
    }

    public boolean checkValidation(String result) {
        return StringUtils.equals(desiredResult, result);
    }
}
