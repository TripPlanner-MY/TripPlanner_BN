package com.tripPlanner.project.domain.signin.repository;

import com.tripPlanner.project.domain.signin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
//import com.tripPlanner.project.domain.signin.entity.UserEntity;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {

    // 아이디 중복 검사
    Optional<UserEntity> findByUserid(String userid);

    // 이메일로 사용자 조회
    Optional<UserEntity> findByEmail(String email);

    // 이메일로 사용자 리스트 조회
    List<UserEntity> findAllByEmail(String email);

    // 아이디 중복 확인
    boolean existsByUserid(String userid);

    // 이메일 중복 확인
    boolean existsByEmail(String email);

    // 아이디와 이메일로 사용자 조회
    Optional<UserEntity> findByUseridAndEmail(String userid, String email);
}

