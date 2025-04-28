package com.tripPlanner.project.domain.makePlanner.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MapDataDto {
    private String streetFullAddress;
    private String businessName;
    private String businessCategory;
    private double XCoordinate;
    private double YCoordinate;
}
