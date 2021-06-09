package com.auth.authServer.controllers;

import com.auth.authServer.PrivateDatabase;
import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/users")
public class UserController {
    public static class UserLogin {
        public static class Response {
            public boolean succeded;
        }

        public String application;
        public String mail;
        public String password;
        public Inquiry inquiry;
    }

    public static class VerifyHuman {
        public enum Reason {
            REGISTRY
        }
        public static class Response {
            public Inquiry inquiry;
            public String captchaImage;
        }
        public Reason reason;
    }

    public static class Registration {
        public enum PreferedRagistrationMode {
            NOT_AVAILABLE,
            MAIL,
            PHONE
        }
        public static class Response {
            public boolean succeded;
        }

        public Inquiry inquiry;
        public String name;
        public String phone;
        public String mail;
        public String password;
        public PreferedRagistrationMode preferedRagistrationMode;
    }

    // TODO: 7/6/21 Bane bad ip VERY IMPORTANT!!!!!

    @PostMapping(value = "/prepare_captcha")
    public VerifyHuman.Response verifyHumanCallback(@RequestBody @NonNull VerifyHuman verifyHuman) {
        VerifyHuman.Response ret = new VerifyHuman.Response();

        try (PrivateDatabase db = Application.getDatabase()) {
            if (verifyHuman.reason == VerifyHuman.Reason.REGISTRY) {
                Captcha captcha = Captcha.newInstance(Application.DEBUG_MODE);
                if (Application.DEBUG_MODE) {
                    System.out.println("SERVICE: users/verifyHuman");
                    System.out.println(Application.getGson().toJson(captcha));
                }
                ret.inquiry = captcha.getInquiry();
                ret.captchaImage = captcha.image;
                db.registerHumanVerificationInquiry(captcha);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    private static Registration.PreferedRagistrationMode getPreferedRegistrationMode(Registration registration) {
        if (registration.preferedRagistrationMode != null) {
            return registration.preferedRagistrationMode;
        } else {
            if (registration.phone != null)
                return Registration.PreferedRagistrationMode.PHONE;
            if (registration.mail != null)
                return Registration.PreferedRagistrationMode.MAIL;
        }
        return Registration.PreferedRagistrationMode.NOT_AVAILABLE;
    }

    @PostMapping(value = "/register")
    public Registration.Response verifyHumanCallback(@RequestBody @NonNull Registration registration) {
        Registration.Response ret = new Registration.Response();

        try (PrivateDatabase db = Application.getDatabase()) {
            PrivateDatabase.Validator validator = new PrivateDatabase.Validator();
            validator.inquiry = registration.inquiry;
            validator.mail = registration.mail;
            validator.phone = registration.phone;
            validator.password = registration.password;
            ret.succeded = db.sendValidationInquiry(validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/register_in_app")
    public Registration.Response verifyHumanCallback2(@RequestBody @NonNull Registration registration) {
        Registration.Response ret = new Registration.Response();

        try (PrivateDatabase db = Application.getDatabase()) {
            PrivateDatabase.Validator validator = new PrivateDatabase.Validator();
            validator.inquiry = registration.inquiry;
            validator.mail = registration.mail;
            validator.phone = registration.phone;
            validator.password = registration.password;
            ret.succeded = db.sendValidationInquiry(validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/login")
    public UserLogin.Response loginCallback(@RequestBody @NonNull UserLogin login) {
        /*
        UserLogin.Response response = new UserLogin.Response();
        try (PrivateDatabase db = Application.getDatabase()) {
            if (login.inquiry != null) {

                UserStatus status = db.getUserStatusByInquiryKey(login.inquiry.inquiry);
                if (status != null) {
                    if (status.inquiry.checkValidation(status.inquiry.desiredResult)) {
                        if (status.state == UserStatus.State.WAITING_RESPONSE_FOR_LOGIN) {
                            UUID id = status.userGlobalId;
                            if (id != null) {
                                // It is a new waiting user
                                User user = db.decodeUser(status.userData, null);
                                if (user != null) {
                                    db.addUser(user);
                                    response.succeded = true;
                                }
                            }
                        }
                    }
                }
                db.removeUserStatusWithInquiryKey(login.inquiry.inquiry);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;

         */
        return null;
    }
}