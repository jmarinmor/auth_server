package com.auth.authServer.controllers;

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

        try (AuthDatabase db = Application.getDatabase()) {
            if (verifyHuman.reason == VerifyHuman.Reason.REGISTRY) {
                Captcha captcha = Captcha.newInstance(Application.DEBUG_MODE);
                if (Application.DEBUG_MODE) {
                    System.out.println("SERVICE: users/verifyHuman");
                    System.out.println(Application.getGson().toJson(captcha));
                }
                ret.inquiry = captcha.getInquiry();
                ret.captchaImage = captcha.image;

                String private_key = null;
                UserStatus status = new UserStatus();
                User user = new User();
                user.gid = UUID.randomUUID();
                status.userGlobalId = user.gid;
                status.userData = db.encodeUser(user, private_key);
                status.state = UserStatus.State.WAITING_HUMAN_VERIFICATION;
                status.inquiry = ret.inquiry;
                status.privateKey = private_key;
                db.setUserStatus(status);
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

        try (AuthDatabase db = Application.getDatabase()) {
            if (registration.inquiry != null) {
                UserStatus status = db.getUserStatusByInquiryKey(registration.inquiry.inquiry);
                if (status != null) {
                    if (status.state == UserStatus.State.WAITING_HUMAN_VERIFICATION) {
                        User user = db.decodeUser(status.userData, status.privateKey);
                        if (user != null) {
                            performRegistryRequest(user, status, db, registration);
                            ret.succeded = true;
                        }
                    }

                }
            } else {
                Registration.PreferedRagistrationMode mode = getPreferedRegistrationMode(registration);
                if (mode == Registration.PreferedRagistrationMode.PHONE) {
                    User user = new User();
                    user.gid = UUID.randomUUID();
                    UserStatus status = new UserStatus();
                    status.userGlobalId = user.gid;
                    performRegistryRequest(user, status, db, registration);
                    ret.succeded = true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    private static void performRegistryRequest(User user, UserStatus status, AuthDatabase db, Registration registration) {
        user.mail = registration.mail;
        user.phone = registration.phone;
        user.password = registration.password;
        user.name = registration.name;

        UserStatus status = new UserStatus();
        status.state = UserStatus.State.WAITING_RESPONSE_FOR_LOGIN;
        status.userData = db.encodeUser(user, status.privateKey);
        status.inquiry = Inquiry.generateNewInquiry();

        Registration.PreferedRagistrationMode mode = getPreferedRegistrationMode(registration);
        switch (mode) {
            case MAIL:
                sendInquiryMail(user.mail, user, status.inquiry);
                db.setUserStatus(status);
                break;
            case PHONE:
                sendInquirySMS(user.phone, user, status.inquiry);
                db.setUserStatus(status);
                break;
        }
    }

    private static void sendInquirySMS(String mail, User user, Inquiry inquiry) {

    }

    private static void sendInquiryMail(String phone, User user, Inquiry inquiry) {

    }

    @PostMapping(value = "/login/{user}")
    public UserLogin.Response loginCallback(@RequestBody @NonNull UserLogin login) {
        UserLogin.Response response = new UserLogin.Response();
        try (AuthDatabase db = Application.getDatabase()) {
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
    }
}