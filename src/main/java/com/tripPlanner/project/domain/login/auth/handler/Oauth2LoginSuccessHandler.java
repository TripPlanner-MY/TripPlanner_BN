package com.tripPlanner.project.domain.login.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tripPlanner.project.domain.login.auth.jwt.JwtTokenProvider;
import com.tripPlanner.project.domain.login.dto.JwtToken;
import com.tripPlanner.project.domain.login.entity.TokenEntity;
import com.tripPlanner.project.domain.login.service.AuthService;
import com.tripPlanner.project.domain.login.service.CustomOAuth2UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class Oauth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // oauth2 로그인 유저 정보 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("Oauth2 로그인 유저 정보" + oAuth2User.getAttributes());

        //oauth2 User 정보 추출
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;

        String provider = oauth2Token.getAuthorizedClientRegistrationId();
        String providerId = CustomOAuth2UserService.getProviderId(oAuth2User,provider);
        String userid = provider + "_" + providerId;

        //토큰 생성
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication,true);
        log.info("jwtToken ..{}",jwtToken);

        response.setHeader("Authorization", "Bearer " + jwtToken.getAccessToken());
        response.setHeader("userid",userid);

        //redis 리프레시 토큰 저장
        long expiration = 7 * 24 * 60 * 60 * 1000; // 2일
        TokenEntity tokenEntity = new TokenEntity(userid, jwtToken.getRefreshToken(),expiration);
        jwtTokenProvider.saveRefreshToken(tokenEntity,true);
        log.info("oauth2 저장된 토큰 엔티티 : {}",tokenEntity);

        //쿠키 저장
        authService.setTokenCookies(response,jwtToken.getAccessToken());

        response.sendRedirect("http://localhost:3000/oauth2/success?userid=" + userid);
        log.info("리액트 홈페이지 이동");

        log.info("JWT 토큰 생성 및 반환 완료: {}" , jwtToken);

    }
}
