package com.tripPlanner.project.domain.login.service;


import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.login.auth.jwt.JwtTokenProvider;
import com.tripPlanner.project.domain.login.dto.JwtToken;
import com.tripPlanner.project.domain.login.dto.LoginRequest;
import com.tripPlanner.project.domain.login.dto.LoginResponse;
import com.tripPlanner.project.domain.login.entity.TokenEntity;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import com.tripPlanner.project.domain.signin.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class LoginService {
    //비밀번호 정규 표현식. 하나 이상의 영어 대문자 , 하나 이상의 특수기호 , 하나 이상의 숫자 , 8글자 13글자 사이
   //private static final String USERPW_RegExp = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[$@$!%*?&])[A-Za-z\\d$@$!%*?&]{8,13}/";

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;  //비밀번호 암호화
    private final JwtTokenProvider jwtTokenProvider;


    public LoginResponse login(LoginRequest loginRequest){ //로그인 기능
        log.info("로그인 서비스 함수 실행");
        log.info("LoginRequest : {}", loginRequest.toString());
        Optional<UserEntity> optionalUser = userRepository.findByUserid(loginRequest.getUserid());
        log.info(optionalUser.toString());
        emptyCheckUserIdAndPassword(loginRequest.getUserid(),loginRequest.getPassword()); //아이디 비밀번호 빈칸검사
        if(optionalUser.isEmpty()){ //loginId와 일치하는 user없으면 에러 리턴
            return LoginResponse.builder()
                    .success(false)
                    .message("유저를 찾을 수 없습니다 !")
                    .build();
        }

        UserEntity userEntity = optionalUser.get();
        if(!passwordEncoder.matches(loginRequest.getPassword(),userEntity.getPassword())){ //User의 password와 입력 password가 다르면 에러 리턴
            return LoginResponse.builder()
                    .success(false)
                    .message("비밀번호가 일치하지 않습니다")
                    .build();
        }

        //PrincipalDetail 생성.
        PrincipalDetail principalDetail = new PrincipalDetail(
                LoginRequest.builder()
                        .userid(userEntity.getUserid())
                        .username(userEntity.getUsername())
                        .role(userEntity.getRole())
                        .provider(userEntity.getProvider())
                        .build(),
                null
        );
        log.info("유저서비스 principal {}",principalDetail);
        //인증 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail,null,principalDetail.getAuthorities());
        log.info("유저 서비스 어덴트 : {} ",authentication);
        //수동으로 SecurityContext에 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //JWT 토큰 생성
        boolean rememberMe = loginRequest.isRememberMe();
        long expiration = rememberMe
                ? 7 * 24 * 60 * 60 * 1000 // 7일(밀리초)
                : 2 * 24 * 60 * 60 * 1000; // 2일(밀리초)
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication,rememberMe);
        TokenEntity tokenEntity = new TokenEntity(userEntity.getUserid(),jwtToken.getRefreshToken(),expiration);
        jwtTokenProvider.saveRefreshToken(tokenEntity,rememberMe);  //redis 에 리프레시토큰 저장
        log.info("토큰엔티티 "+tokenEntity);
        
        return LoginResponse.builder()
                .userid(userEntity.getUserid())
                .username(userEntity.getUsername())
                .accessToken(jwtToken.getAccessToken())   //access토큰 반환
                .refreshToken(jwtToken.getRefreshToken())     //refresh토큰 반환
                .success(true)
                .message("로그인 성공")
                .build();
    }

    //빈칸 검사 함수
    private void emptyCheckUserIdAndPassword(String userid,String password){
        log.info("빈칸 검사 실행");
        if(userid == null || userid.trim().isEmpty()){
            throw new IllegalArgumentException("아이디를 입력해주세요");
        }

        if(password ==null || password.trim().isEmpty()){
            throw new IllegalArgumentException("비밀번호를 입력해주세요");
        }

        else{
            log.info("값이 입력되어있습니다.");
        }
    }


}




