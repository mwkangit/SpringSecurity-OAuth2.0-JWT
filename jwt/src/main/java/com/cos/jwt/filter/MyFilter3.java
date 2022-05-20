package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터3");
        // 여기서 PrintWriter out = response.getWriter();
        // out.print("안녕"); 이라고 하면 여기서 걸리면서 프로그램이 끝난다.
        // chain에 넘겨줘야 프로그램이 진행된다.
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        // cos라는 이름의 토큰을 생성하였다고 가정하자.
        // cos 토큰이 도착한 것이 아니면 인증을 하지 않고 컨트롤러로 들어가지 못하게 한다.
        // 이 필터는 시큐리티 필터가 적용되기 전에 실행되어야 한다.
        // id, pw가 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들어주고 그걸 응답해줘야 한다.
        // 이후 다음 요청에 토큰이 넘어오면 토큰을 검증하면 된다. (RSA, HS256)
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")){
                filterChain.doFilter(req, res);
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
