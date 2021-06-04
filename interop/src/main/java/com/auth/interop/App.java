package com.auth.interop;

import org.apache.commons.validator.routines.EmailValidator;

public class App {

    public static class DemandResult {
        public boolean canInit;
        public String capcheId;

        public DemandResult(boolean canInit, Captcha captcha) {
            this.canInit = canInit;
            if (captcha != null)
                this.capcheId = captcha.id;
        }
    }


    public static class InitRequest {
        public String email;
        public String capchaId;
        public String capchaValue;
        public String password;

        public boolean isValidEmail() {
            return EmailValidator.getInstance().isValid(email);
        }
    }

    public static class InitResult {

        public boolean validRequest;
        public boolean validMail;
        public boolean validCaptcha;
        public boolean validPassword;

        public InitResult(boolean validRequest, boolean validMail, boolean validCaptcha, boolean validPassword) {
            this.validRequest = validRequest;
            this.validMail = validMail;
            this.validCaptcha = validCaptcha;
            this.validPassword = validPassword;
        }
    }

    public static class InitMessage {
        public String userName;
        public String email;
    }
}
