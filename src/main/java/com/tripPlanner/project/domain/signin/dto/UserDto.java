package com.tripPlanner.project.domain.signin.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class UserDto {

    private String userid;
    private String img;
    private String username;
    private String password;
    private String repassword;
    private String email;
    private int birth;

    private String gender;
    private String role;
}
