package com.auth.authServer.controllers;

import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.Application;
import com.auth.interop.ErrorCode;
import com.auth.interop.Validator;
import com.auth.interop.*;
import com.auth.interop.requests.RegistrationRequest;
import com.auth.interop.requests.UpdateUserRequest;
import com.auth.interop.requests.VerifyHumanRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    // TODO: 7/6/21 Bane attacking ip VERY IMPORTANT!!!!!

    @PostMapping(value = "/prepare_captcha")
    public VerifyHumanRequest.Response verifyHumanCallback(@RequestBody @NonNull VerifyHumanRequest verifyHumanRequest) {
        VerifyHumanRequest.Response ret = new VerifyHumanRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            if (verifyHumanRequest.reason == VerifyHumanRequest.Reason.REGISTRY) {
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

    // This function send a code to user
    // Needs: the response generated in prepare_captcha
    @PostMapping(value = "/register")
    public RegistrationRequest.Response registerAccountCallback(@RequestBody @NonNull RegistrationRequest registrationRequest) {
        RegistrationRequest.Response ret = new RegistrationRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            Validator validator = new Validator();
            validator.inquiry = registrationRequest.inquiry;
            validator.mail = registrationRequest.mail;
            validator.phone = registrationRequest.phone;
            validator.password = registrationRequest.password;
            // this functions send a mail or phone code
            ret.errorCode = db.sendValidationInquiry(validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    // This function finally activate an account
    // Needs: the response generated in register
    @PostMapping(value = "/verify")
    public RegistrationRequest.Response verifyAccountCallback(@RequestBody @NonNull RegistrationRequest registrationRequest) {
        RegistrationRequest.Response ret = new RegistrationRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            Validator validator = new Validator();
            validator.inquiry = registrationRequest.inquiry;
            validator.mail = registrationRequest.mail;
            validator.phone = registrationRequest.phone;
            validator.password = registrationRequest.password;
            ret.errorCode = db.verifyUser(validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/generate_token")
    public RegistrationRequest.Response generateTokenCallback(@RequestBody @NonNull RegistrationRequest registrationRequest) {
        RegistrationRequest.Response ret = new RegistrationRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            Validator validator = new Validator();
            validator.inquiry = registrationRequest.inquiry;
            validator.mail = registrationRequest.mail;
            validator.phone = registrationRequest.phone;
            validator.password = registrationRequest.password;
            ret.response = db.generateTokenForUser(validator);
            if (ret.response == null || ret.response.userData == null)
                ret.errorCode = ErrorCode.INVALID_USER;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/update_user")
    public UpdateUserRequest.Response updateUserCallback(@RequestBody @NonNull UpdateUserRequest registration) {
        UpdateUserRequest.Response ret = new UpdateUserRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            Validator validator = new Validator();
            validator.inquiry = registration.inquiry;
            validator.mail = registration.mail;
            validator.phone = registration.phone;
            validator.password = registration.password;
            ret.errorCode = db.updateUser(registration.user, validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}