package com.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('a1')")
    public String hello() {
        return "hello";
    }

    @GetMapping("/ma")
    @PreAuthorize("hasRole('a4')")
    public String ma() {
        return "main";
    }

    @GetMapping("/hehe")
    @PreAuthorize("hasRole('a1')")
    public String hehe() {
        return "hehe";
    }

}
