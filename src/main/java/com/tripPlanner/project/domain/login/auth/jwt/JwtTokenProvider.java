package com.tripPlanner.project.domain.login.auth.jwt;

import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.login.dto.JwtToken;
import com.tripPlanner.project.domain.login.dto.LoginRequest;
import com.tripPlanner.project.domain.login.entity.TokenEntity;
import com.tripPlanner.project.domain.login.entity.TokenRepository;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    @Getter
    public String secretKey;
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;
    private final TokenRepository tokenRepository;
    private final RedisTemplate<String,String> redisTemplate;

    @PostConstruct
    public void init(){
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 액세스 토큰 생성
    public String generateAccessToken( Authentication authentication) {
        //Authentication 에서 PrincipalDetail 추출
        PrincipalDetail principalDetail = (PrincipalDetail) authentication.getPrincipal(); 
        
        //PrincipalDetail 에서 필요한 정보 추출
        String userid = principalDetail.getLoginRequest().getUserid();
        String username = principalDetail.getUsername();
        String provider = principalDetail.getLoginRequest().getProvider();
        String role = principalDetail.getLoginRequest().getRole();
        log.info("userid : {} , 프로바이더 : {} , 롤 ~ : {}",userid,provider,role);

        Claims claims = Jwts.claims().setSubject(userid); // Jwt payload에 userid 저장
        claims.put("username",username);
        claims.put("provider",provider);
        claims.put("role",role);  //일단 확인해보고 안되면 고정 값 넣기

        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + accessTokenExpiration)) // 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, secretKey) // HMAC SHA256 알고리즘 사용
                .compact(); // 토큰 생성 후 반환
    }

    // 리프레시 토큰 생성
    public String generateRefreshToken(Authentication authentication,boolean rememberMe ) {
        PrincipalDetail principalDetail = (PrincipalDetail) authentication.getPrincipal();
        String userid = principalDetail.getLoginRequest().getUserid();

        Claims claims = Jwts.claims().setSubject(userid); // Jwt payload에 userid 저장
        Date now = new Date();
        long expiration = rememberMe ? refreshTokenExpiration * 7 / 2 : refreshTokenExpiration; //1주일 또는 2일

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiration)) // 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, secretKey) // HMAC SHA256 알고리즘 사용
                .compact(); // 토큰 생성 후 반환

    }
    //토큰 생성후 dto 로 사용하기 위해 만든 메서드
    public JwtToken generateToken(Authentication authentication,boolean rememberMe){

        String accessToken = generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(authentication,rememberMe);

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // Userid 추출 메서드
    public String getUserIdFromToken(String token){
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody(); // 토큰 페이로드 가져옴
            String userid = claims.getSubject(); //Subject 에서 userid 추출
            return userid;
        }catch(ExpiredJwtException e){
            return e.getClaims().getSubject();
        }
    }

    //토큰 복호화 메서드
    public Authentication getTokenInfo(String token){
        log.info("복호화 간다잇 ~~");
        //토큰 분해
        Claims claims = parseClaims(token);
        
        //토큰에서 필요한 정보 추출
        String userid = claims.getSubject(); //userid 추출
        String username = (String) claims.get("username");
        String provider = (String) claims.get("provider");
        String role = (String) claims.get("role");

        log.info("복호화된 토큰 정보: userid={}, provider={}, role={}, username={}", userid, provider, role,username);

        // PrincipalDetail 생성
        PrincipalDetail principalDetail = new PrincipalDetail(
                LoginRequest.builder()
                        .userid(userid)
                        .username(username)
                        .provider(provider)
                        .role(role)
                        .build(),null
        );

        return new UsernamePasswordAuthenticationToken(principalDetail,null,principalDetail.getAuthorities());
    }

    //토큰 Claims 가져오기
    public Claims parseClaims(String accessToken){
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(accessToken).getBody();
    }

    //토큰 유효성 검사
    public boolean validateToken(String token){
        try{
            //리프레시 토큰 블랙리스트 처리 여부 확인
            if(isTokenBlacklisted(token)){
                log.warn("이미 블랙리스트 처리된 토큰입니다 : {}",token);
                return false;
            }

            //토큰 유효성 검사
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true; //유효하다면 true
        }catch(ExpiredJwtException e){
            log.warn("토큰 만료됨 {}" , e.getMessage());
        }catch(JwtException e){
            log.warn("토큰이 유효하지 않음 {}",e.getMessage());
        }catch(Exception e){
            log.warn("알 수 없는 오류 {}",e.getMessage());
        }
        return false; //유효하지 않은 경우 !
    }

//    //토큰 만료시간 정보 추출 메서드
//    public Date getExpirationDateFromToken(String token){
//        return Jwts.parserBuilder()
//                .setSigningKey(secretKey)
//                .build()
//                .parseClaimsJws(token)
//                .getBody()
//                .getExpiration(); //만료 시간 확인
//    }
    
    //엑세스 토큰 재생성 메서드
    public String regenAccessToken(Authentication authentication,String refreshToken){
        log.info("엑세스 토큰을 재생성합니다");

        if(!validateToken(refreshToken)){
            //토큰이 유효하지 않을 때
            log.info("리프레시 토큰 만료. 로그아웃처리");
            throw new IllegalArgumentException("리프레시 토큰 만료. 로그아웃처리");
        }
        //redis 에 있는 refreshToken 조회
        String userid = getUserIdFromToken(refreshToken);

        log.info("리프레시 토큰에서 추출한 사용자ID {} ",userid);

        String redisKey = "refreshToken:"+userid;
        String storedRefreshToken = redisTemplate.opsForValue().get(redisKey);
        log.info("stroed리프레시 {}", storedRefreshToken);
        if(storedRefreshToken == null){
            log.warn("Redis에서 리프레시 토큰을 찾을 수 없습니다");
            throw new IllegalArgumentException("Redis에서 리프레시 토큰을 찾을 수 없습니다");
        }

        if(!storedRefreshToken.equals(refreshToken)){
            log.warn("Redis에 저장된 리프레시 토큰과 요청된 리프레시 토큰이 일치하지 않습니다");
            throw new IllegalArgumentException("Redis에 저장된 리프레시 토큰과 요청된 리프레시 토큰이 일치하지 않습니다");
        }

        String newAccessToken = generateAccessToken(authentication);
        log.info("새로운 엑세스 토큰이 생성되었습니다: {}", newAccessToken);
        return newAccessToken;
    }
    
    //Redis 토큰저장 메서드
    public void saveRefreshToken(TokenEntity tokenEntity, boolean rememberMe){
        String key = "refreshToken" +":"+ tokenEntity.getId() ;
        long expiration = rememberMe ? refreshTokenExpiration * 7 / 2 : refreshTokenExpiration; //rememberMe 여부에 따라 7일 or 2일

        //Redis에 저장 및 TTL 설정
        redisTemplate.opsForValue().set(key,tokenEntity.getRefreshToken(),expiration,TimeUnit.MILLISECONDS);

    }
    
    //블랙리스트 처리 된 토큰 검사 메서드
    public boolean isTokenBlacklisted(String token){
        String blacklistedTokens = "blacklistedTokens";
        return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(blacklistedTokens,token));
    }

    //비밀번호 재설정을 위한 토큰을 발급하는 메서드
    public String generateResetToken(String userid, String email) {
        Claims claims = Jwts.claims().setSubject(userid);
        claims.put("email", email);
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }



}
