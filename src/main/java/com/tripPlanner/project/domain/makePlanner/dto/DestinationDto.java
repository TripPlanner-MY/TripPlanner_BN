package com.tripPlanner.project.domain.makePlanner.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DestinationDto {
    private String name;
    private double x;
    private double y;
    private String address;
    private String category;
    private String image;
    private String username;  // Planner의 username
    private int plannerID;
    private int day;
    private int dayOrder;
}
