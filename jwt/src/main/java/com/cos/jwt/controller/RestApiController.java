package com.cos.jwt.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin // 인증이 필요한 것은 거부하고 인증이 필요없는 것만 허용하게 된다. 인증이 필요한 것에 접근하고 싶은 경우 CorsConfig를 만든다.
@RestController
public class RestApiController {

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }


}
