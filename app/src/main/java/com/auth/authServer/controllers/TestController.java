package com.auth.authServer.controllers;

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
