package com.tripPlanner.project.domain.login.dto;

import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginRequest {
    private String userid;
    private String password;
    private String username;
    private String role;
    private boolean rememberMe; //리멤버미 여부

    private String provider;
    private String providerId;

}
