package com.tripPlanner.project.domain.login.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {

    private String userid;  //유저 아이디
    private String username;  //유저 이름
    private boolean success;  //성공여부
    private String message;  //응답메시지
    private String accessToken;
    private String refreshToken;

}
