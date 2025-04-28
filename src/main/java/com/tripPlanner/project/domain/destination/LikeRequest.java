package com.tripPlanner.project.domain.destination;

import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class LikeRequest {
    private Planner plannerID;
}
