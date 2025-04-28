package com.tripPlanner.project.domain.login.service;

import com.tripPlanner.project.domain.login.auth.PrincipalDetail;
import com.tripPlanner.project.domain.login.dto.LoginRequest;

import com.tripPlanner.project.domain.signin.entity.UserEntity;
import com.tripPlanner.project.domain.signin.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PrincipalDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("UserDetailService..." );
        UserEntity userEntity = userRepository.findByUserid(username)
                .orElseThrow(()-> new UsernameNotFoundException("유저 정보를 찾을 수 없습니다 : " + username));

        //엔티티 -> dto
        LoginRequest loginRequest = LoginRequest.builder()
                .userid(userEntity.getUserid())
                .password(userEntity.getPassword())
                .role(userEntity.getRole())
                .provider(userEntity.getProvider())
                .providerId(userEntity.getProviderId())
                .build();

        return new PrincipalDetail(loginRequest);
    }
}






