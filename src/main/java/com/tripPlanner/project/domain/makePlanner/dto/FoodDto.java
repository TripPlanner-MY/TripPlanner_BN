package com.tripPlanner.project.domain.makePlanner.dto;

import com.tripPlanner.project.domain.makePlanner.entity.Food;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FoodDto {
    public String id;
    public String name;
    public double x;
    public double y;
    public String locationPhoneNumber;
    public String locationPostalCode;
    public String locationFullAddress;
    public String streetPostalCode;
    public String address;
    public String category;
    public String image;

    // Dto -> Entity
    public static Food dtoToEntity(FoodDto foodDto) {
        return Food.builder()
                .id(foodDto.getId())
                .name(foodDto.getName())
                .x(foodDto.getX())
                .y(foodDto.getY())
                .locationPhoneNumber(foodDto.getLocationPhoneNumber())
                .locationPostalCode(foodDto.getLocationPostalCode())
                .locationFullAddress(foodDto.getLocationFullAddress())
                .streetPostalCode(foodDto.getStreetPostalCode())
                .address(foodDto.getAddress())
                .category(foodDto.getCategory())
                .image(foodDto.getImage())
                .build();
    }

    // Entity -> DTO
    public static FoodDto entityToDto(Food food) {
        return FoodDto.builder()
                .id(food.getId())
                .name(food.getName())
                .x(food.getX())
                .y(food.getY())
                .locationPhoneNumber(food.getLocationPhoneNumber())
                .locationPostalCode(food.getLocationPostalCode())
                .locationFullAddress(food.getLocationFullAddress())
                .streetPostalCode(food.getStreetPostalCode())
                .address(food.getAddress())
                .category(food.getCategory())
                .image(food.getImage())
                .build();
    }
}
