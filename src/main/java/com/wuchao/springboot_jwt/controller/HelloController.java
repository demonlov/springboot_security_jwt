package com.wuchao.springboot_jwt.controller;


import com.wuchao.springboot_jwt.config.JwtTokenUtil;
import com.wuchao.springboot_jwt.entity.ResponseEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.RestController;

/**
 * @author WuChao
 * @version 1.0
 * @date 2020/2/25 12:03
 */

@RestController
public class HelloController {
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String hello() {
        return "hello jwt";
    }


    @GetMapping("/a")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String a() {
        return "hello jwt";
    }

    @GetMapping("/refreshToken")
    public String refreshToken(String token) {
        Boolean aBoolean = jwtTokenUtil.checkedTokenTime(token);
        if (aBoolean) {
            String s = jwtTokenUtil.refreshToken(token);
            return s;
        }
        return null;
    }


    @GetMapping("/userInfo")
    public ResponseEntity everyone() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (! (authentication instanceof AnonymousAuthenticationToken)) {
            // 登入用户
            return new ResponseEntity(HttpStatus.OK.value(), "You are already login", authentication.getPrincipal());
        } else {
            return new ResponseEntity(HttpStatus.OK.value(), "You are anonymous", null);
        }
    }

}

