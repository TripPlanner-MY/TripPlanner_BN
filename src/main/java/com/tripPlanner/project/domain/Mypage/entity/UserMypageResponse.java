package com.tripPlanner.project.domain.Mypage.entity;


import com.tripPlanner.project.domain.makePlanner.dto.PlannerDto;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserMypageResponse {
    private UserEntity user;
    private List<PlannerDto> planners;
}
