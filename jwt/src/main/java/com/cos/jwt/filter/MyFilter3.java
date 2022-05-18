package com.cos.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터3");
        // 여기서 PrintWriter out = response.getWriter();
        // out.print("안녕"); 이라고 하면 여기서 걸리면서 프로그램이 끝난다.
        // chain에 넘겨줘야 프로그램이 진행된다.
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
