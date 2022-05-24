package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter 가지고 있는데 그 필터 중 BasicAuthenticationFilter가 있다.
// 권한이나 인증이 필요한 특정 주소 요청 시 위 필터를 반드시 접근하게 된다.
// 만약 권한이나 인증이 필요한 주소가 아닌 경우 이 필터를 접근하지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 된다. BasicAuthenticationFilter을 상속받았기 때문이다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        // Authorization이라는 헤더가 없으면 실행하는 코드이다. 즉, 헤더가 있는지 확인하는 것이다.
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인해야 한다.
        // "Bearer "을 ""로 만든다.
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        // 이전에 토큰 생성시 사용한 알고리즘과 시크릿 키를 입력하고 jwtToken을 서명한다.
        // 토큰 생성시 username이라는 클레임을 작성했으며 그것을 꺼내오는 것이다.
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        // username이 제대로 들어오면 서명이 잘된 것이다.
        // 서명이 정상적으로 되었을 시 실행되는 코드이다.
        if(username != null){
            System.out.println("username 정상");
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // JwtAuthenticationFilter처럼 정상 로그인 시 Authentication을 만드는게 아닌 Authentication 객체를 강제로 만드는 것이다.
            // 서비스를 통해 로그인을 진행하는 것이 아닌 임의로 Authentication 객체를 생성하는 것이기 때문에 패스워드에 null을 입력해도 된다.
            // username이 null이 아닌것을 확인하여 정상 서명 상태이므로 authentication 만들어도 된다.
            // 마지막 매개변수로 권한을 알려준다. 즉, 정상적인 로그인 과정이 아니고 JWT 토큰 서명이 정상일 때 생성하는 Authentication 객체이므로 권한을 알려준다.
            // 마지막 강의에서 이 부분에서 세션이 만들어지지 않아서(객체가 생성되지 않아서) null이 발생하여 NullPointException과 함께 인가가 되지 않는다.
            // 이 메소드 가장 위의 super.doFilterInternal을 주석처리 해야한다. 허용하면 위에서 응답 1번, 아래에서 응답 1번으로 중복되어 오류가 발생한다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 이 코드는 시큐리티를 저장할 수 있는 세션 공간을 찾은 것이다.
            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장한 것이다.
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request, response);
        return;

    }
}
