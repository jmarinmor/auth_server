package com.auth.authServer.controllers;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.KeyDatabase;
import com.auth.interop.Captcha;
import com.auth.interop.requests.SetPanicPublicKeyRequest;
import com.auth.interop.requests.VerifyHumanRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

@RestController
@RequestMapping("/owner")
public class OwnerController {

    @PostMapping(value = "/set_panic_pk")
    public SetPanicPublicKeyRequest.Response setPanicPublicKeyCallback(@RequestBody @NonNull SetPanicPublicKeyRequest request) {
        SetPanicPublicKeyRequest.Response ret = new SetPanicPublicKeyRequest.Response();

//        try (KeyDatabase db = Application.getKeyDatabase()) {
//            ret.errorCode = db.setPanicPublicKey(request);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        return ret;
    }
}
