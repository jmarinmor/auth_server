package com.auth.authServer.controllers;

import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.Application;
import com.servers.interop.requests.*;
import com.servers.key.model.KeyDatabase;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    // TODO: 7/6/21 Bane attacking ip VERY IMPORTANT!!!!!

    @PostMapping(value = "/prepare_captcha")
    public VerifyHumanRequest.Response verifyHumanCallback(@RequestBody @NonNull VerifyHumanRequest verifyHumanRequest) {
        VerifyHumanRequest.Response ret = new VerifyHumanRequest.Response();

        try (AuthDatabase db = Application.getAuthDatabase()) {
            if (verifyHumanRequest.reason == VerifyHumanRequest.Reason.REGISTRY) {
                Captcha captcha = Captcha.newInstance(Application.DEBUG_MODE);
                if (Application.DEBUG_MODE) {
                    System.out.println("SERVICE: users/verifyHuman");
                    System.out.println(Application.getGson().toJson(captcha));
                }
                ret.inquiry = captcha.getInquiry();
                ret.captchaImage = captcha.image;
                //db.registerInquiry(captcha, null, null);
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

        try (AuthDatabase db = Application.getAuthDatabase()) {
            Validator validator = new Validator();
            //validator.inquiry = registrationRequest.inquiry;
            validator.mail = registrationRequest.mail;
            validator.phone = registrationRequest.phone;
            validator.password = registrationRequest.password;
            // this functions send a mail or phone code
            //ret.errorCode = db.sendInquiry(Inquiry.Reason.REGISTER_VALIDATION, validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    // This function finally activate an account
    // Needs: the response generated in register
    @PostMapping(value = "/verify")
    public CommandResponse<VerifyUser.Response> verifyAccountCallback(@RequestBody @NonNull VerifyUser request) {
        CommandResponse<VerifyUser.Response> ret = new CommandResponse<>();

        try (AuthDatabase db = Application.getAuthDatabase()) {
//            Validator validator = new Validator();
//            validator.inquiry = request.inquiry;
//            validator.mail = request.mail;
//            validator.phone = request.phone;
//            validator.password = request.password;
//            UUID id = db.verifyUser(validator);
//            if (id != null) {
//                ret.response = new VerifyUser.Response(id);
//                ret.errorCode = ErrorCode.SUCCEDED;
//            } else {
//                ret.errorCode = ErrorCode.INVALID_USER;
//            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/generate_token")
    public RegistrationRequest.Response generateTokenCallback(@RequestBody @NonNull RegistrationRequest registrationRequest) {
        RegistrationRequest.Response ret = new RegistrationRequest.Response();

        try (   AuthDatabase adb = Application.getAuthDatabase();
                KeyDatabase kdb = Application.getKeyDatabase()) {
//            Validator validator = new Validator();
//            validator.inquiry = registrationRequest.inquiry;
//            validator.mail = registrationRequest.mail;
//            validator.phone = registrationRequest.phone;
//            validator.password = registrationRequest.password;
//            ret.response = adb.generateTokenForUser(kdb, validator);
//            if (ret.response == null || ret.response.userData == null)
//                ret.errorCode = ErrorCode.INVALID_USER;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/update_user")
    public UpdateUserRequest.Response updateUserCallback(@RequestBody @NonNull UpdateUserRequest registration) {
        UpdateUserRequest.Response ret = new UpdateUserRequest.Response();

        try (   AuthDatabase adb = Application.getAuthDatabase();
                KeyDatabase kdb = Application.getKeyDatabase()) {
//            Validator validator = new Validator();
//            validator.inquiry = registration.inquiry;
//            validator.mail = registration.mail;
//            validator.phone = registration.phone;
//            validator.password = registration.password;
//            ret.errorCode = adb.updateUser(registration.user, kdb, validator);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}