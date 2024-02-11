package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Mertcan Özarslan
 */

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    // create dummy user to db
//    @PostConstruct
    public void createUser() {
        userService.createUserWithRole();
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/auth")
    public String auth() {
        return "welcome admin";
    }

    @GetMapping(value = "/logout-new")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        SecurityContextHolder.getContext().setAuthentication(null);

        return "logged out";
    }


}
