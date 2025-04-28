package com.tripPlanner.project.domain.login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtToken {
    String grantType;
    String accessToken;
    String refreshToken;

}
