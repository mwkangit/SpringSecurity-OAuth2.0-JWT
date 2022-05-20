package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter라는 필터가 존재한다.
// login 요청해서 username, password 전송하면 (post) UsernamePasswordAuthenticationFilter 필터가 실행된다.
// 현재 이 필터는 SecurityConfig에서 formlogin().disable()로 인해 실행되지 않는다.
// 이 필터를 다시 SecurityConfig에 등록해야 한다.

// 이 어노테이션으로 AuthenticationManager을 생성자처럼 받는다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // AuthenticationManager을 이용해서 로그인 시도를 하는데 이때 실행되는 메소드가 아래 메소드이다.
    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수이다. 이때 실행된다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwTAuthenticationFilter : 로그인 시도중");

        // 1. username, password를 받아서
        // 2. 정상인지 로그인 시도를 해본다.
        return super.attemptAuthentication(request, response);
    }
}
