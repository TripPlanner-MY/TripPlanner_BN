package com.tripPlanner.project.domain.makePlanner.repository;

import com.tripPlanner.project.domain.makePlanner.entity.Food;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FoodRepository extends JpaRepository<Food,String>  {
    @Query("SELECT fd FROM Food AS fd WHERE (fd.x BETWEEN :xStart AND :xEnd) AND (fd.y BETWEEN :yStart AND :yEnd)")
    List<Food> selectFoodAll(
            @Param("xStart") double xStart,
            @Param("yStart") double yStart,
            @Param("xEnd") double xEnd,
            @Param("yEnd") double yEnd
    );

    @Query("SELECT fd FROM Food AS fd WHERE (fd.locationFullAddress LIKE %:areaname% or fd.address LIKE %:areaname%) and fd.name LIKE %:word%")
    List<Food> searchFood(
            @Param("word") String word,
            @Param("areaname") String areaname
    );

    @Query("SELECT fd FROM Food AS fd WHERE fd.locationFullAddress LIKE %:areaname% or fd.address LIKE %:areaname% ")
    List<Food> searchAreaFood(
            @Param("areaname") String areaname
    );
}
