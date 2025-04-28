package com.tripPlanner.project.domain.board;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BoardDto {
    private int plannerID;
    private String plannerTitle;
    private LocalDateTime createAt;
    private int day;
    private String username;
    private String thumbnailImage;
    private String area;
    private String description;
    private String userId;
    private String userProfileImg;
    private boolean isPublic;
}