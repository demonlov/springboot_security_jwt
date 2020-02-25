package com.wuchao.springboot_jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wuchao.springboot_jwt.config.JwtTokenUtil;
import com.wuchao.springboot_jwt.entity.ResponseEntity;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * @author WuChao
 * @version 1.0
 * @date 2020/2/25 11:19
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserDetailsService userDetailsService;
    private JwtTokenUtil jwtTokenUtil;
    // 会从 Spring Security 配置文件那里传过来
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserDetailsService userDetailsService,JwtTokenUtil jwtTokenUtil) {
        super(authenticationManager);
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(jwtTokenUtil.getHeader());
        //获取令牌有效时间
        Long aLong = jwtTokenUtil.TokenTime(header);
        long time =  new Date().getTime()-aLong ;
        boolean flag = (time < jwtTokenUtil.getRefreshToken()) && time > 0;
        ObjectMapper mapper = new ObjectMapper();
        ResponseEntity responseEntity = new ResponseEntity();
        if (!flag) {
            if (aLong ==-1) {
                response.setHeader("Content-Type", "application/json;charset=UTF-8");
                responseEntity.setStatus(2000);
                responseEntity.setMsg("token 已经失效");
                response.setStatus(HttpStatus.OK.value());
                response.getWriter().write(mapper.writeValueAsString(responseEntity));
                return;
            }
            response.setHeader("Content-Type", "application/json;charset=UTF-8");
            responseEntity.setStatus(400);
            responseEntity.setMsg("token 即将失效");
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write(mapper.writeValueAsString(responseEntity));
            return;
        }

        if (header != null && StringUtils.isNotEmpty(header)) {
            String username = jwtTokenUtil.getUsernameFromToken(header);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                // 验证token和用户是否匹配
                if (jwtTokenUtil.validateToken(header, userDetails)) {
                    // 然后把构造UsernamePasswordAuthenticationToken对象
                    // 最后绑定到当前request中，在后面的请求中就可以获取用户信息
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            chain.doFilter(request, response);
        }else{
            chain.doFilter(request, response);
                return;
        }
    }
}
