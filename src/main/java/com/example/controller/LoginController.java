package com.example.controller;

import com.example.domain.ResponseResult;
import com.example.domain.User;
import com.example.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
public class LoginController {

    @Autowired
    private LoginService loginService;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user, HttpServletResponse response){
        ResponseResult responseResult = loginService.doLogin(user);
        if (!Objects.isNull(responseResult) && responseResult.getCode()  == 200) {
            Map<String,String> data =  (HashMap)responseResult.getData();
            Cookie cookie = new Cookie("token",data.get("token"));
            response.addCookie(cookie);
        }
        return responseResult;
    }

    @GetMapping("/user/logout")
    public ResponseResult logout() {
       return loginService.logout();
    }
}
