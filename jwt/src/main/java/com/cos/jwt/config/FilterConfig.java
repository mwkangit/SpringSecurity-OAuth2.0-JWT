package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


// 이때 시큐리티 필터가 모두 실행된 후 이 필터들이 실행된다.
// addFilterAfter로 설정해도 이 클래스의 필터가 나중에 실행된다.
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        // 모든 요청에 대해 다 하라.
        bean.addUrlPatterns("/*");
        // 우선 순위 설정으로 낮은 번호가 필터 중에서 가장 먼저 실행된다.
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2(){
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        // 모든 요청에 대해 다 하라.
        bean.addUrlPatterns("/*");
        // 우선 순위 설정으로 낮은 번호가 필터 중에서 가장 먼저 실행된다.
        bean.setOrder(1);
        return bean;
    }
}
