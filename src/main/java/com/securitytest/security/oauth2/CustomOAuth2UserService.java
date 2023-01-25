package com.securitytest.security.oauth2;

import com.securitytest.UserRepository;
import com.securitytest.entity.User;
import com.securitytest.security.auth.UserDetailsCustom;
import com.securitytest.security.oauth2.provider.GoogleUserInfo;
import com.securitytest.security.oauth2.provider.KaKaoUserInfo;
import com.securitytest.security.oauth2.provider.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    //구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    //OAuthAttributes: OAuth2UserService를 통해 가져온 OAuth2User의 attribute를 담을 클래스
    //User: 엔티티 클래스
    //UserRepository: 엔티티 클래스를 DB에 접근하게 해주는 인터페이스
    //SessionUser: 세션에 사용자 정보를 저장하기 위한 Dto 클래스
    //CustomOAuth2UserService: 구글 로그인 이후 가져온 사용자의 정보(email, name, picture 등)들을 기반으로 가입 및 정보수정, 세션 저장 등의 기능 지원
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return processOAuth2User(userRequest, oAuth2User);
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청~~");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("kakao")) {
            System.out.println("카카오 로그인 요청~~");
            oAuth2UserInfo = new KaKaoUserInfo((Map) oAuth2User.getAttributes());
            System.out.println(oAuth2UserInfo.toString());
        } else {
            System.out.println("우리는 구글과 카카오만 지원해요 ㅎㅎ");
        }

        Optional<User> userOptional =
                userRepository.findByProviderAndProviderId(oAuth2UserInfo.getProvider(), oAuth2UserInfo.getProviderId());

        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            // user가 존재하면 update 해주기
            user.setEmail(oAuth2UserInfo.getEmail());
            userRepository.save(user);
        } else {
            // user의 패스워드가 secret이기 때문에 OAuth 유저는 일반적인 로그인을 할 수 없음.
            user = User.builder()
                    .userId(oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId())
                    .email(oAuth2UserInfo.getEmail())
                    .username(oAuth2UserInfo.getName())
//                    .password(bCryptPasswordEncoder.encode("secret"))
                    .role("ROLE_USER")
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getProviderId())
                    .build();
            userRepository.save(user);
        }
        System.out.println(user.toString());
        return new UserDetailsCustom(user, oAuth2User.getAttributes());
    }
}
