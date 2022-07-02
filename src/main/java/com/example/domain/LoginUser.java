package com.example.domain;

import com.alibaba.fastjson.annotation.JSONField;
import com.fasterxml.jackson.annotation.JsonFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

@Data
@NoArgsConstructor
public class LoginUser implements UserDetails {

    private User user;
    private Collection<String> powers;

    @JSONField(serialize = false) // GrantedAuthority 存入 redis 时是不序列化的，会报错
    private Collection<GrantedAuthority> authorities = new ArrayList<>();

    public LoginUser(User user,Collection<String> powers) {
        this.user = user;
        this.powers = powers;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        // 将 authorities 设置为成员属性，若不为空的化直接返回，不需要再进行 powers 的转换，速度会快一些
        // 若权限不为 null 则直接返回
        if (authorities.size() > 0) {
            return authorities;
        }

        // 添加角色信息
        for (String power : powers) {
           authorities.add(new SimpleGrantedAuthority("ROLE_"+power));
        }

        /*
           在 SpringSecurity 中，用户的 权限信息和角色信息 都是存在
           同一个集合中的，但是角色信息有 ROLE_ 前缀，所以在我们自定义
           UserDetails 时一定要区分

         */

        // 添加权限信息
        for (String power : powers) {
            authorities.add(new SimpleGrantedAuthority(power));
        }

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
