package com.auth.authServer.controllers;

import com.auth.interop.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/students")
public class UserController {
    @GetMapping(value = "/{studentId}")
    public User getTestData(Integer studentId) {
        User user = new User("hola");
        return user;
    }
}