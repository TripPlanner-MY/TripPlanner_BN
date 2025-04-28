package com.tripPlanner.project.domain.makePlanner.dto;

import com.tripPlanner.project.domain.makePlanner.entity.Accom;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccomDto {
    public int id;
    public String name;
    public double x;
    public double y;
    public String locationPhoneNumber;
    public String locationPostalCode;
    public String locationFullAddress;
    public String streetPostalCode;
    public String address;
    public String category;
    public String hygieneCategory;
    public String image;

    // Dto -> Entity
    public static Accom dtoToEntity(AccomDto accomDto) {
        return Accom.builder()
                .id(accomDto.getId())
                .name(accomDto.getName())
                .x(accomDto.getX())
                .y(accomDto.getY())
                .locationPhoneNumber(accomDto.getLocationPhoneNumber())
                .locationPostalCode(accomDto.getLocationPostalCode())
                .locationFullAddress(accomDto.getLocationFullAddress())
                .streetPostalCode(accomDto.getStreetPostalCode())
                .address(accomDto.getAddress())
                .category(accomDto.getCategory())
                .hygieneCategory(accomDto.getHygieneCategory())
                .build();
    }

    // Entity -> DTO
    public static AccomDto entityToDto(Accom accom) {
        return AccomDto.builder()
                .id(accom.getId())
                .name(accom.getName())
                .x(accom.getX())
                .y(accom.getY())
                .locationPhoneNumber(accom.getLocationPhoneNumber())
                .locationPostalCode(accom.getLocationPostalCode())
                .locationFullAddress(accom.getLocationFullAddress())
                .streetPostalCode(accom.getStreetPostalCode())
                .address(accom.getAddress())
                .category(accom.getCategory())
                .hygieneCategory(accom.getHygieneCategory())
                .build();
    }
}
