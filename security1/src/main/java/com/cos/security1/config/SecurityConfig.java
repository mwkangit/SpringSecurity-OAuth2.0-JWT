package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화, postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    // 패스워드 암호화
    // 해당 메소드의 리턴되는 오브젝트를 IoC로 등록해준다.
    // bean cycle의 영향으로 main에 작성한다.
//    @Bean
//    public BCryptPasswordEncoder encodePwd(){
//        return new BCryptPasswordEncoder();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/") // /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함. 아직 인가가 안됌.
                .userInfoEndpoint() // oauth 순서 -> 1. 코드 받기(인증됨) 2.엑세스토큰 받기(시큐리티 서버가 구글 로그인한 사용자의 정보에 접근 가능한 권한 생긴 것이다.) 3. 사용자 프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함. 4-2. (정보가 부족할 수 있다.) 구글 제공하는 사용자 프로필에 이메일, 전화번호, 이름, 아이디가 있을 때 쇼핑몰을 운영하면 추가적으로 집주소 등이 필요하다. or 백화점 -> vip등급, 일반등급. 이때 추가적인 회원가입 창으로 추가 정보 입력하게 해야한다. 하지만 정보가 충분하다면 구글 제공 정보로 회원가입 다 한다.
                .userService(principalOauth2UserService);// Tip. 구글 로그인이 완료되면 코드를 받는 것이 아닌 엑세스토큰 + 사용자프로필정보를 한번에 받는다. // 현재 매개변수로 들어간 클래스가 후처리를 진행하는 클래스이다.

    }
}
