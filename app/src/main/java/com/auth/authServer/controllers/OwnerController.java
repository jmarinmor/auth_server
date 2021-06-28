package com.auth.authServer.controllers;

import com.servers.interop.requests.SetPanicPublicKeyRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
