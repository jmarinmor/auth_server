package com.auth.interop;

import org.apache.commons.lang3.StringUtils;

import java.util.Random;
import java.util.UUID;

public class Inquiry {
    public enum Action {
        REGISTER_USER(1),
        VALIDATE_USER(2),
        REGISTER_USER_TO_APPLICATION(3);

        private int type;
        Action(int type) {this.type = type;}
    }

    public static class ActionParams {
        public User.PublicData user;
        public UUID userId;
        public String applicationCode;
        public Validator validator;

        public ActionParams() {
        }

        public ActionParams(User.PublicData user) {
            this.user = user;
        }

        public ActionParams(Validator validator) {
            this.validator = validator;
        }

        public ActionParams(User.PublicData user, Validator validator) {
            this.user = user;
            this.validator = validator;
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
