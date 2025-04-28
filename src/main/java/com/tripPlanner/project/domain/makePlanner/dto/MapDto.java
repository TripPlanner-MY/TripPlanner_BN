package com.tripPlanner.project.domain.makePlanner.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MapDto {
    private double latitude;
    private double longitude;
    private int zoomlevel;
}
