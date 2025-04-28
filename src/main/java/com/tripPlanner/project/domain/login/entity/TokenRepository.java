package com.tripPlanner.project.domain.login.entity;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends CrudRepository<TokenEntity,String> {
    Optional<TokenEntity> findByRefreshToken(String refreshToken); //Access Token 찾기
}
