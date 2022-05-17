package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // view를 리턴한다
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // 일반 사용자 정보 접근
    @GetMapping("/test/login")
    public @ResponseBody String loginTest(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails){ // Authentication으로 DI(의존성 주입)
        // @AuthenticationPrincipal로 세션 정보에 접근할 수 있다.
        // 이때 @AuthenticationPrincipal은 UserDetails 타입을 받기 때문에 UserDetails를 상속받은 PrincipalDetails로 바로 받을 수 있다.
        // 즉, Authentication을 DI하는 방법과 어노테이션을 이용하여 정보에 접근하는 방법으로 2가지 접근법이 있다.
        // 둘다 같은 데이터를 가진다.
        System.out.println("/test/login ============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        // getUser은 PrincipalDetails의 User 객체 정보를 가져오는 것이다.
        System.out.println("authentication: " + principalDetails.getUser());

        System.out.println("userDetails: " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    // OAuth의 정보 접근
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOauthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth){ // Authentication으로 DI(의존성 주입)
        // @AuthenticationPrincipal로 세션 정보에 접근할 수 있다.
        // 이때 @AuthenticationPrincipal은 UserDetails 타입을 받기 때문에 UserDetails를 상속받은 PrincipalDetails로 바로 받을 수 있다.
        // 즉, Authentication을 DI하는 방법과 어노테이션을 이용하여 정보에 접근하는 방법으로 2가지 접근법이 있다.
        // 둘다 같은 데이터를 가진다.
        // OAuth로 접근하면 UserDetails가 아닌 OAuth2User로 받는다.
        System.out.println("/test/login ============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        // getUser은 PrincipalDetails의 User 객체 정보를 가져오는 것이다.
        System.out.println("authentication: " + oAuth2User.getAttributes());
        System.out.println("oauth2User: " + oauth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    // 주소 2개 넣은 것이다
    // localhost:8080/
    // localhost:8080
    @GetMapping({"", "/"})
    public String index(){
        // 머스테시 사용
        // 현재 설정에 따라 index.mustache 파일을 찾게 된다
        // 이것을 바꾸려고 config 파일을 만든다
        return "index";
    }


    // OAuth 로그인을 해도 PrincipalDetails로 받는다.
    // 일반 로그인을 해도 PrincipalDetails로 받는다.
    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails : " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    // spring security가 /login url 요청을 낚아채서 이 부분 실행 안되고 있다.
    // securityconfig 파일 생성 후 작동한다
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    // 회원 가입 페이지 출력
    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    // 회원 가입 완료시 가는 url
    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
//        userRepository.save(user); // 회원가입 잘 된다. but 비밀번호 : 1234 일 경우 -> 시큐리티로 로그인을 할 수 없다. 이유는 패스워드가 암호화가 안되었기 때문이다.
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);

        return "redirect:/loginForm";
    }

    // @Secured 없을 때에는 SecurityConfig의 permitAll로 인해 로그인 안해도 접근 가능하다.
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    // @Secured 없을 때에는 SecurityConfig의 permitAll로 인해 로그인 안해도 접근 가능하다.
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
}
