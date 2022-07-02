package com.example.SecurityFilter;

import com.example.domain.LoginUser;
import com.example.utils.JwtUtil;
import com.example.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 *      该过滤器是自定义的过滤器。
 *      在该项目中，我们使用 token 的方式来完成认证，因此服务器在接收到用户请求后，首先要将 token 的信息解析出来，
 *   让后在交给 SpringSecurity。SpringSecurity再对这个解析的信息进行认证，判断其是否能访问系统
 *      通过这个例子，我们可以了解如下知识点：
 *          1.SpringSecurity的认证过程
 *          2.如何为SpringSecurity添加自定义过滤器
 *          3.SpringSecurity是如何完成认证的
 *      通用这个例子，我们应该具备根据实际需求自定义登入方式。
 *     其实SpringSecurity的功能很简单，就是对资源权限控制、认证和授权。对资源的权限控制可以让我们使用 SpringSecurity
 *   提供的接口对特定的资源设置特定的权限。而认证就是 SpringSecurity 拿到一个 SpringSecurity 内部定义的 token 对象
 *   然后进行认证即可，SpringSecurity 不管这个 token 对象是如何生成的，只要这个 token 对象符合 SpringSecurity 的
 *   规范，就能被 SpringSecurity 进行认证操作。除此之外，还有一点需要提醒的是，SpringSecurity 认证时是在 SecurityContextHolder
 *   这个容器内获取要认证的 token 的；因此我们将 token 封装后，还需要将其放入 SecurityContextHolder
 *
 */

/**
 *  该过滤器的实现逻辑如下:
 *  1.当有用户发起访问请求时，该过滤器会获取请求头中的 token 的值，并将其解码
 *  2.使用解码后的 token 到 redis 内获取相应的数据
 *  3.将 redis 内获取的数据封装成 SpringSecurity 的 token 对象
 *  4.将该 token 对象交给 SecurityContextHolder，SpringSecurity的底层会在这里获取token并完成认证
 */

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 获取请求的 token 字符串
        String tokenStr = request.getHeader("token");
        // 判断 token 是否为空
        if (!StringUtils.hasText(tokenStr)) {
            filterChain.doFilter(request,response);
            return;
        }
        // 解析 token 字符串
        String userId = null;
        try {
            Claims claims = JwtUtil.parseJWT(tokenStr);
            userId = claims.getSubject();
        } catch (Exception e) {
            throw new RuntimeException("非法的 token");
        }
        // 使用解析后的字符串到 redis 内获取登入对象
        LoginUser loginUser = redisCache.getCacheObject("login:" + userId);
        if(Objects.isNull(loginUser)){
            throw new RuntimeException("用户未登录");
        }

        // 将登入对象封装成 SpringSecurity 的 token 对象并放入 SecurityContextHolder
        UsernamePasswordAuthenticationToken userToken =
                new UsernamePasswordAuthenticationToken(loginUser,null,loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(userToken);
        filterChain.doFilter(request,response);

    }
}
