package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {


    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수이다.
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 내 서버의 기본정보가 있다.
        // registrationId로 어떤 oauth로 로그인 했는지 확인가능하다.
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
        // 이미 사용자프로필을 가져와서 엑세스토큰은 의미가 없긴하다.
        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 이 정보로 회원가입을 진행한다.
        // 순서 : 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(oauth-client 라이브러리가 받는다) -> 바로 자동으로 코드를 통해 AccessToken을 요청 -> AccessToken을 받는 것까지 userRequest의 정보이다.
        // userRequest 정보를 통해 -> 회원프로필을 받아야함(이때 사용되는 함수가 loadUser이며 loadUser함수를 호출한다) -> 구글로부터 회원프로필을 받음
        System.out.println("getAttributes = " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        } else{
            System.out.println("구글, 페이스북, 네이버 로그인만 지원합니다!");
        }

        // 구글로만 로그인 시 사용
//        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
//        String providerId = oAuth2User.getAttribute("sub"); // 구글에서 Id는 sub이다. 107850419880594031570
//        // 사실 OAuth로 로그인하면 username, password가 필요없는데 형식상 만드는 것이다.
//        String username = provider+"_"+providerId; // google_107850419880594031570
//        String password = bCryptPasswordEncoder.encode("겟인데어");
//        String email = oAuth2User.getAttribute("email"); // cabookis@gmail.com
//        String role = "ROLE_USER";

        // 구글, 페이스북 로그인 시 사용
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        // 사실 OAuth로 로그인하면 username, password가 필요없는데 형식상 만드는 것이다.
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        // 이미 회원가입이 되어있을 수 있으므로 UserRepository @AutoWired하여 가져온다.
        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else{
            System.out.println("로그인을 이미 한 적이 있습니다!");
        }


        // 리턴 타입이 OAuth2User이므로 가능하다.
        // 이 객체가 시큐리티 세션의 Authentication에 들어간다.
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
