package com.example.service;

import com.example.domain.ResponseResult;
import com.example.domain.User;

public interface LoginService {

    ResponseResult doLogin(User user);

    ResponseResult logout();
}
