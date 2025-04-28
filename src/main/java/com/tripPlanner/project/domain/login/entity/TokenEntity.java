package com.tripPlanner.project.domain.login.entity;


import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@RedisHash(value ="token")//Redis에 저장될 key 의 네임스페이스 설정
@AllArgsConstructor
@Data
public class TokenEntity {

    @Id
    private String id; //Redis 의 key
    private String refreshToken; //리프레시 토큰
    @TimeToLive //TTL 설정
    private long expiration;

}
