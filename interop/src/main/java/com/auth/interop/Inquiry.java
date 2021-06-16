package com.auth.interop;

import org.apache.commons.lang3.StringUtils;

import java.util.Random;
import java.util.UUID;

public class Inquiry {
    public static class Action {
        public enum Type {
            REGISTER_USER(1),
            VALIDATE_USER(2);

            private int type;
            Type(int type) {this.type = type;}
        }

        public Type type;
        public User.PublicData user;
        public Validator validator;

        public static Action newRegisterUser() {
            Action action = new Action();
            action.type = Type.REGISTER_USER;
            return action;
        }

        public static Action newValidateUser() {
            Action action = new Action();
            action.type = Type.VALIDATE_USER;
            return action;
        }
    }

    public static class Response {
        public ErrorCode errorCode;
        public UUID id;
        public Inquiry debugDesiredResponse;
    }

    private static final Random mRandom = new Random();

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
