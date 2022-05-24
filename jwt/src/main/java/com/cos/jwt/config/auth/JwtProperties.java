package com.cos.jwt.config.auth;

// 이렇게 관리하고 JwtAuthenticationFilter에서 사용하는 것이 좋다.
// 관리하기 편하며 실수를 방지할 수 있다.
public interface JwtProperties {
    String SECRET = "cos"; // 우리 서버만 알고 있는 시크릿 키
    int EXPIRATION_TIME = 864000000; // 10일 (1/1000초)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
