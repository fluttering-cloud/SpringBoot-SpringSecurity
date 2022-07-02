package com.example.service.impl;

import com.example.domain.LoginUser;
import com.example.domain.ResponseResult;
import com.example.domain.User;
import com.example.service.LoginService;
import com.example.utils.JwtUtil;
import com.example.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Objects;

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult doLogin(User user) {
        // 将用户信息封装成 token 对象交
        UsernamePasswordAuthenticationToken token
                = new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());

        // 用SpringSecurity提供的认证功能完成认证
        Authentication authenticate = authenticationManager.authenticate(token);

        // 查看认证信息是否为空，为空表示失败
        if(Objects.isNull(authenticate)) {
            throw new RuntimeException("登入失败");
        }
        // 获取登入对象的ID
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userId = loginUser.getUser().getId().toString();
        // 将认证信息进行jwt加密
        String jwt = JwtUtil.createJWT(userId);
        //authenticate存入redis
        redisCache.setCacheObject("login:"+userId,loginUser);
        //把token响应给前端
        HashMap<String,String> map = new HashMap<>();
        map.put("token",jwt);
        return new ResponseResult(200,"登陆成功",map);
    }

    @Override
    public ResponseResult logout() {

        // 因为注销的请求里肯定包含了 token 信息，所以 SecurityContextHolder 可以直接拿到对应的对象
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser= (LoginUser) authentication.getPrincipal();
        Long userId = loginUser.getUser().getId();
        // 拿到对应的登入对象后，删除对应 redis 内的数据
        redisCache.deleteObject("login:" + userId);
        return new ResponseResult(200,"注销成功",null);
    }
}
