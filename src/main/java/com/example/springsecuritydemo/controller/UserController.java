package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;

/**
 * @author Mertcan Özarslan
 */

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/home")
    public String home(){
        return "home";
    }

    @PostConstruct
    public void createUser(){
        userService.createUserWithRole(passwordEncoder);
    }

    @GetMapping("/auth")
    public String auth(){
        System.out.println("test");
        return "welcome admin";
    }




}
