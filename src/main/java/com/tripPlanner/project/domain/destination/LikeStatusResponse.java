package com.tripPlanner.project.domain.destination;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LikeStatusResponse {
    private boolean isLiked;  // 사용자가 좋아요를 눌렀는지 여부
    private int likeCount;    // 현재 좋아요 개수
}