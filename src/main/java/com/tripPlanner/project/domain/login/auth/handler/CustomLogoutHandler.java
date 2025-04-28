package com.tripPlanner.project.domain.login.auth.handler;

import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.login.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final RedisTemplate<String,String> redisTemplate;
    private final AuthService authService;
    private static final String COOKIE_NAME = "accessToken";
    private static final String REDIS_REFRESHTOKEN_NAME = "refreshToken:";

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("현재 SecurityContext 인증 정보: {}", SecurityContextHolder.getContext().getAuthentication());
        log.info("어덴티케이션 !!!!,{}",authentication);
        String accessToken = checkAccessTokenFromCookie(request);
        if(accessToken ==null){
            log.warn("로그아웃 요청에 필요한 토큰이 없습니다");
        }else{
            log.info("로그아웃 요청. 엑세스 토큰을 제거합니다.");
            authService.invalidateCookie(response);

        }

        String refreshToken = checkRefreshTokenFromRedis(authentication);
        System.out.println("메서드 리프레시 토큰" + refreshToken);
        if(refreshToken != null){
            //리프레시 토큰 블랙리스트로 이동
            String blackListKey = "blacklistedTokens";
//            long expiration = 3600; //블랙리스트 저장 시간(1시간)
            redisTemplate.opsForSet().add(blackListKey,refreshToken);  //유효기간 설정은 보류
            log.info("리프레시 토큰이 블랙리스트 처리되었습니다.");
            log.info("처리된 블랙리스트 토큰 {}",refreshToken);
        }else{
            log.info("Redis 에서 토큰을 찾을 수 없습니다");
        }

        deleteRedisRefreshToken(authentication);

        log.info("로그아웃 처리 완료");
    }

    //쿠키가 있는지 확인하는 메서드
    public String checkAccessTokenFromCookie(HttpServletRequest request){
        //쿠키가 없으면 null 리턴
        if(request.getCookies() ==null){
            return null;
        }
        //쿠키가 있다면 쿠키값 반환
        for(Cookie cookie : request.getCookies()){
            if(COOKIE_NAME.equals(cookie.getName())){
                System.out.println("쿠키네임"+cookie);
                return cookie.getValue();
            }
        }
        return null;
    }

    //Redis 에 있는 리프레시 토큰 가져오는 메서드
    private String checkRefreshTokenFromRedis(Authentication authentication){
        if(authentication == null){
            System.out.println("어덴티케이션 없음");
            return null;
        }

        Object principal = authentication.getPrincipal();

        if(principal instanceof PrincipalDetail){
            String userid = ((PrincipalDetail) principal).getName();
            String redisKey = REDIS_REFRESHTOKEN_NAME+userid;
            System.out.println("레디스 아이디 : " + redisKey);
            return redisTemplate.opsForValue().get(redisKey);
        }else{
            return null;
        }
    }
    
    //Redis 데이터 삭제 메서드
    private void deleteRedisRefreshToken(Authentication authentication){
        if(authentication == null || authentication.getPrincipal() == null){
            log.warn("인증정보가 존재하지 않습니다. Redis 키를 삭제할 수 없습니다.");
            return ;
        }

        Object principal = authentication.getPrincipal();
        if(principal instanceof PrincipalDetail){
            String userid = ((PrincipalDetail)principal).getName();
            String redisKey = REDIS_REFRESHTOKEN_NAME+userid;
            redisTemplate.delete(redisKey);
            log.info("Redis 에서 리프레시 토큰 삭제:{}",redisKey);
        }else{
            log.warn("principal 타입이 잘못됨. Redis키 삭제 불가능");
        }
    }





}
