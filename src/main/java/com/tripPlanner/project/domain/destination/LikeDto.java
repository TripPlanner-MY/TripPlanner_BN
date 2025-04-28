package com.tripPlanner.project.domain.destination;

import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import lombok.*;

import java.time.LocalDateTime;


@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LikeDto {

    private Long id; // Like ID
    private int plannerID;
    private String plannerTitle; // Planner 제목
    private String area; // Planner 지역
    private int day; // 여행 일수
    private String description; // Planner 설명
    private LocalDateTime createdAt; // 좋아요 생성 날짜
}