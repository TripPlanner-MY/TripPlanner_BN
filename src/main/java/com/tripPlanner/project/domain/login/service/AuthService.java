package com.tripPlanner.project.domain.login.service;

import com.tripPlanner.project.domain.login.auth.jwt.JwtTokenProvider;
import com.tripPlanner.project.domain.login.dto.LoginResponse;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import com.tripPlanner.project.domain.signin.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseCookie;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;



    @Service
    @Slf4j
    @RequiredArgsConstructor
    public class AuthService {

        private final JwtTokenProvider jwtTokenProvider;
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JavaMailSender javaMailSender;
        private final RedisTemplate<String,String> redisTemplate;

        private final ConcurrentHashMap<String,String> verificationCodes = new ConcurrentHashMap<>();

        //JWT 시크릿 키 가져오기
        private String getKey(){
            return jwtTokenProvider.getSecretKey();
        }

        public LoginResponse refreshAccessToken(Authentication authentication, String refreshToken){
            try{
                // 엑세스 토큰 재검증 및 재생성
                String newAccessToken = jwtTokenProvider.regenAccessToken(authentication,refreshToken);

                return LoginResponse.builder()
                        .success(true)
                        .message("새로운 엑세스 토큰이 발급되었습니다")
                        .accessToken(newAccessToken)
                        .refreshToken(refreshToken) //기존 리프레시 토큰 반환
                        .build();
            }catch(IllegalArgumentException e){
                log.warn("리프레시 토큰이 만료되었거나 유효하지 않습니다",e.getMessage());
                return LoginResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .build();
            }
        }

        //쿠키 저장 메서드
        public void setTokenCookies(HttpServletResponse response, String accessToken) {
            ResponseCookie cookie = ResponseCookie.from("accessToken", accessToken)
                    .httpOnly(true)
                    .secure(true) // HTTPS 사용 시 true로 변경
                    .sameSite("None") // CORS 요청에서도 쿠키 허용
                    .path("/")
                    .maxAge(30 * 60) // 30분 유효
                    .build();

            log.info("쿠키쿠키 : {}",cookie);
            response.addHeader("Set-Cookie", cookie.toString());
        }
    
    //인증 메일 발송 메서드
    public void sendAuthMail(String to,String subject,String body){
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        message.setFrom("wlscksals@gmail.com");

        javaMailSender.send(message);

    }

    //인증 코드 생성
    public String generateAuthCode(String email){
        String code = String.valueOf((int)((Math.random() * 900000) + 100000));
        verificationCodes.put(email,code);
        return code;
    }

    public boolean verifyCode(String email,String code){
        return verificationCodes.containsKey(email) && verificationCodes.get(email).equals(code);
    }

    public void removeCode(String email){
        verificationCodes.remove(email);
    }

    //비밀번호 변경 저장 메서드
    public void updatePassword(String userid,String newPassword){
        UserEntity userEntity = userRepository.findByUserid(userid).orElseThrow(()->new IllegalArgumentException("유저를 찾을 수 없습니다"));
        userEntity.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(userEntity);
    }

    public List<UserEntity> findUserIdByEmail(String email){
        return userRepository.findAllByEmail(email);
    }

    public boolean existsByUserid(String userid){
        return userRepository.existsByUserid(userid);
    }

    public Optional<UserEntity> findByUseridAndEmail(String userid,String email) {

        return userRepository.findByUseridAndEmail(userid,email);
    }

        //쿠키를 바로 삭제하는 메서드
        public static void invalidateCookie(HttpServletResponse response){
            Cookie cookie = new Cookie("accessToken",null);
            cookie.setMaxAge(0);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
        }

    public String resolveRefreshToken(HttpServletRequest request){
        String userid = request.getHeader("userid");

        String redisKey = "refreshToken:"+ userid;
        String refreshToken = redisTemplate.opsForValue().get(redisKey);
        log.info("추출한 유저 아이디: {}",userid);
        log.info("리프레시 토큰은 ?: {}",refreshToken);
        if (refreshToken == null) {
            log.warn("Redis에서 리프레시 토큰을 찾을 수 없습니다. User-Id: {}", userid);
            return null;
            }
        return refreshToken;
        }



}
