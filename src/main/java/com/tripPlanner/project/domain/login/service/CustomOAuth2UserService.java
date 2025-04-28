package com.tripPlanner.project.domain.login.service;

import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.login.dto.LoginRequest;


import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import com.tripPlanner.project.domain.signin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService{

    private final UserRepository userRepository;
//    private final BCryptPasswordEncoder passwordEncoder;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);  // oauth2
        log.info("getAttributes : " + oAuth2User.getAttributes());
        System.out.println("userRequest.getAccessToken().getTokenType().getValue() : "+ userRequest.getAccessToken().getTokenType().getValue());

        String provider = userRequest.getClientRegistration().getRegistrationId(); //provider 값 (naver, google 등)
        String providerId = getProviderId(oAuth2User,provider);
        String userid = provider + "_" + providerId;

        log.info("userid 는 ? " + userid);

        Optional<UserEntity> optionalUser = userRepository.findByUserid(userid);
        UserEntity userEntity;

        if(optionalUser.isEmpty()){
            userEntity = createUserEntity(userid,oAuth2User,"ROLE_USER",provider, providerId);
            //로그인 할 때 사용자 정보가 없다면 그대로 회원가입이 되도록 진행
            userRepository.save(userEntity);
        }else{
            userEntity = optionalUser.get();
        }

        //LoginRequest 생성
        LoginRequest loginRequest = LoginRequest.builder()
                .userid(userEntity.getUserid())
                .password(null)
                .username(userEntity.getUsername())
                .role(userEntity.getRole())
                .rememberMe(true)
                .provider(provider)
                .providerId(providerId)
                .build();

        PrincipalDetail principalDetail = new PrincipalDetail();
        principalDetail.setLoginRequest(loginRequest);
        principalDetail.setAttributes(oAuth2User.getAttributes());

        return principalDetail;
    }

    //provider 에 따라 providerId를 다르게 처리
    public static String getProviderId(OAuth2User oAuth2User, String provider){
        switch(provider){
            case "google" :
                return oAuth2User.getAttribute("sub");
            case "naver" :
                return (String) ((Map<String,Object>) oAuth2User.getAttribute("response")).get("id");
            case "kakao" :
                return oAuth2User.getAttribute("id").toString();
            case "instagram" :
                return oAuth2User.getAttribute("id");
            default :
                throw new IllegalArgumentException("지원하지 않는 제공자입니다.");
        }
    }

    //UserEntity 만드는 함수
    private UserEntity createUserEntity(String userid, OAuth2User oAuth2User, String role,String provider, String providerId){
        String username;
        String email;
        String gender = "unknown";

        switch(provider){
            case "google" :
                username = oAuth2User.getAttribute("name");
                email = oAuth2User.getAttribute("email");
                break;
            case "naver" :
                username = (String) ((Map<String,Object>) oAuth2User.getAttribute("response")).get("nickname");
                email = (String) ((Map<String,Object>) oAuth2User.getAttribute("response")).get("email");
                break;
            case "kakao" :
                Map<String, Object> properties = oAuth2User.getAttribute("properties");
                username = (String) properties.get("nickname");
                Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");
                email = (String) kakaoAccount.get("email");
                break;
            case "instagram" :
                username = ""; //아직 미구현
                email = "";
                break;
            default :
                throw new IllegalArgumentException("사용하지 않는 제공자입니다");
        }
        return UserEntity.builder()
                .userid(userid)
                .username(username)
                .email(email)
                .gender(gender)
                .role("ROLE_USER")
                .planners(new ArrayList<>()) // 초기화된 planners 설정
                .provider(provider)
                .providerId(providerId)
                .build();
    }

}
