package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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
        try {
            // request.getInputStream을 문자열로 바꿔서 출력하는 방법이다.
            // 현재 x-www-form-urlencoded로 오기 때문에 '&'를 기준으로 파싱해야 한다.
            // 하지만 JSON으로 요청이 오는 경우가 많기 때문에 아래에 JSON 처리방법을 사용한다.
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input=br.readLine()) != null){
//                System.out.println(input);
//            }

            // JSON으로 요청온 데이터를 ObjectMapper로 파싱하여 바로 User 오브젝트에 입력하는 코드이다.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 이 바이트 스트림 내부에 username, password 담겨있다.
            System.out.println(request.getInputStream());

            // 로그인 시도 시 토큰을 하나 만들어줘야 한다.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이제 위에 생성된 토큰으로 로그인 시도를 한다.
            // PrincipalDetailsService의 loadByUsername 함수가 이때 실행된다. 이때 loadByUsername은 username만 매개변수로 받는다.
            // password는 스프링 내부에서 db와 함께 처리해준다(자동). 위에서 토큰만들때 처리해준다.
            // authenticationManager를 거쳐서 인증이 되면 Authentication 객체를 반환한다. 즉, 정상이면 authentication이 리턴된다.
            // 로그인이 되어 Authentication 객체가 생성되면 db에 로그인 시도하는 사용자의 username, password가 일치하는 row가 있는 것이다.
            // 이 Authentication에 로그인한 정보가 담긴다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 오브젝트로 반환되므로 타입캐스팅(다운캐스팅) 해준다.
            // Authentication 객체는 세션 영역에 저장해야 된다. 여기서 출력이 되면 로그인이 완료 되었다는 뜻이다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());
            System.out.println("1===============================");

            // 생성된 Authentication 객체를 반환한다.
            // return 하면 Authentication이 세션에 저장된다!!!
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것이다.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. 단지 권한 처리 때문에 세션에 넣는 것이다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("2===============================");

        // 2. 정상인지 로그인 시도를 해본다. 즉, db에서 아이디와 패스워드가 유효한지 검사한다. 이때 authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다. 즉, 그 클래스 내부의 loadUserByUsername 메소드가 실행된다.
        // 3. 이렇게 PrincipalDetails가 반환되면 이 객체를 세션에 담고
        // 4. JWT 토큰을 만들어서 응답해주면 된다. 세션에 넣어야 SecurityConfig에 설정한 권한(인가)를 통과할 수 있다.

        // 오류 발생시 null을 반환한다.
        return null;
    }


    // 위의 attemptAuthentication 실행 이후에 인증이 정상적으로 되었으면 자동으로 실행되는 메소드이다.
    // 여기에 JWT 토큰을 생성하여 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 패스워드 잘못 입력 시 Unauthorized 메시지와 함께 401 에러가 발생한다.
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻이다.");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // 빌더 패턴으로 JWT 토큰을 생성한다.
        // RSA 방식이 아닌 Hash 암호화방식이다. 그래서 서버만의 secret값을 마지막에 설정한 것이다.
        String jwtToken = JWT.create()
                // subject는 principalDetails.getUsername()로 해도 되며 크게 의미 없다.
                .withSubject("cos토큰")
                // 만료시간이며 토큰이 언제까지 유효한지 정하는 것이다. 만료시간이 어느정도 짧아야 토큰이 탈취되어도 안전하다.
                // 1/1000 초 단위이므로 1000이 1초이다. 지금은 10분을 입력한 것이다.
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                // withclaim은 비공개 클레임이다.
                // 넣고 싶은 key, value를 막 넣어도 된다.
                // 토큰에 담긴다.
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                // 매개변수로 들어가는 secret은 사실 이 서버만 아는 고유한 값이어야 한다.
                // 여기서는 예시로 cos라고 간편하게 한 것이다.
                .sign(Algorithm.HMAC512("cos"));

        // 이러한 방식으로 헤더에 넣어서 토큰을 응답한다.
        // 이때 Bearer 입력 후 띄어쓰기 해야하는 것에 주의하자.
        // 이제 응답 헤더에 JWT 토큰이 있는 것을 볼 수 있다.
        // 이제 토큰을 이용하여 중요 정보(민감 정보)에 접근할 수 있는 필터를 만든다.
        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
