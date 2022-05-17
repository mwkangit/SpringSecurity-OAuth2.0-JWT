package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다.
// session 공간은 같은데 시큐리티가 자신만의 시큐리티 세션 공간을 가지게 되며 키값으로 구분한다.(Security ContextHolder라는 키값에 세션 정보를 저장한다.)
// session에 들어갈 수 있는 정보(오브젝트 타입)는 정해져 있다. => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 한다.
// User 오브젝트 타입 => UserDetails 타입 객체이어야 한다.
// 그래서 UserDetails를 상속받는다.
// 이제 PrincipalDetails는 UserDetails와 같은 타입이다.

// Security Session 에 정보를 저장하는데 여기에 저장할 수 있는 객체는 Authentication 객체이며 이 객체에 유저 정보를 저장할 때 유저 정보는 UserDetails 타입이어야 한다.
// security session에 있는 정보를 꺼내면 Authentication객체가 나오면 그 안에서 userDetails로 유저 정보를 볼 수 있다.


import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    // 현재 유저 정보는 User 오브젝트가 가지고 있다.
    private User user; // 콤포지션
    private Map<String, Object> attributes;

    //일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳
    // 현재 user.getRole()의 리턴 타입은 String이어서 변환해서 반환해야 한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ArrayList는 컬렉션의 자식이다.
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            // 여기서 String을 리턴할 수 있다.
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    // 해당 User의 패스워드를 리턴하는 곳
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 해당 User의 유저이름을 리턴하는 곳
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 해당 User의 계정이 만료되었는지 리턴 - 아니오
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 해당 User의 계정이 잠겼는지 리턴 - 아니오
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 해당 User의 계정의 비밀번호가 많이 사용했는지 리턴 - 아니오
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 해당 User가 활성화 되어있는지 리턴 - 아니오
    @Override
    public boolean isEnabled() {

        // false 하는 경우
        // 우리 사이트에서 1년동안 회원이 로그인을 안하면 휴면 계정으로 하기로 했다.
        // 현재시간 - 최근 로그인 시간이 1년 초과시 return false하면 휴면이라고 저장된다.

        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
