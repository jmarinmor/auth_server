package com.auth.authServer.controllers;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.requests.SetPanicPublicKeyRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping(value = "/test1")
    public String setPanicPublicKeyCallback() {
        System.out.println("test1");
        return "test1";
    }

}
