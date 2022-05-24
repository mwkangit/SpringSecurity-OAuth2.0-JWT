package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration // IoC할 수 있게 만든다.
@EnableWebSecurity // 이 시큐리티를 활성화 한다.
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // CorsConfig에서 등록한 CorsFilter을 이용한다.
    private final CorsConfig corsConfig;
    private final UserRepository userRepository;

    // BCryptPasswordEncoder을 IoC 등록한다
    // cycle의 영향으로 주석 후후 man 파일에 IoC를 진행한다.
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // addFilter을 하면 addFilterBefore이나 addFilterAfter을 사용해서 시큐리티 필터 시작 전이나 후에 실행되게 하라고 한다.
        // 아래 BasicAuthenticationFilter를 쓰면 SpringFilterChain의 이 필터가 실행되기 전에 내가 만든 필터가 실행된다는 뜻이다.
        // 하지만 시큐리티 필터에 생성한 필터를 걸어줄 필요없이 IoC로 필터를 적용할 수 있다.
        // 만약 시큐리티 필터보다 먼저 내 필터를 실행하고 싶으면 before로 시큐리티 필터의 가장 앞을 설정하면 된다.
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        // jwt설정의 기본이다.
        // stateless 서버로 만들겠다는 뜻이다.
        // 세션을 사용하지 않겠다는 뜻이다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // @CrossOrigin은 인증이 없을 때 실행되고 시큐리티 필터에 필터를 등록해야 인증이 있을 때 실행된다.
                // 이걸로 이제 요청 시 시큐리티의 로그인 창이 뜨지 않는다.
                .addFilter(corsConfig.corsFilter())
                // jwt 서버이므로 폼 로그인을 하지 않은다.
                .formLogin().disable()
                // 기본적인 http 로그인 방식을 사용하지 않는 것이다.
                .httpBasic().disable()
                // formLogin().disable()로 실행되지 않는 필터를 실행되게 하려고 다시 적용한다.
                // id, pw 로 로그인을 진행하는 필터이므로 AuthenticationManger이라는 파라미터를 줘야 한다.
                // WebSecurityConfigurerAdapter 를 상속받았는데 이 메소드에 AuthenticationManager가 포함되어 있어서 그대로 사용한다.
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

    }
}
