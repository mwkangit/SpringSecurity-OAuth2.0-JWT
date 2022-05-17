package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// @Service 로 운영한다.
// 시큐리티 설정에서 loginProcessingUrl("/login");을 해놓은 상태이다.
// 그러므로 /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행된다.
// 즉, @Service로 PrincipalDetailsService 가 자동으로 IoC 등록이 된다. 그래서 자동 호출 되는 것이다.
// loadUserByUsername의 파라미터인 username은 폼의 username과 동일해야 한다. 즉, 폼에서 username2로 코드를 변경하면 매칭이 안된다. 만약 바꾸고 싶다면 SecurityConfig에 .usernameParameter("username2");를 작성해야 한다.
// 여기선 폼에서 그냥 username으로 하여 기본값을 사용한다.

@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 시큐리티 session(내부 Authentication(내부 UserDetails))
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username이라는 이름으로 저장된 것이 있는지 확인하는 작업이다.
        User userEntity = userRepository.findByUsername(username);
        // 유저가 있으면 UserDetails로 반환한다.
        if(userEntity != null){
            return new PrincipalDetails(userEntity);
        }
        // 없으면 null 반환한다.
        return null;
    }
}
