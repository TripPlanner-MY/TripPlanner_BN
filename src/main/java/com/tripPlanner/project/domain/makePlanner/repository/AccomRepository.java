package com.tripPlanner.project.domain.makePlanner.repository;

import com.tripPlanner.project.domain.makePlanner.entity.Accom;
import com.tripPlanner.project.domain.makePlanner.entity.Food;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccomRepository extends JpaRepository<Accom,String> {
    // 중심좌표를 기준으로 특정 지역의 Accom만을 조회하는 쿼리문 (zoom level에 따른 것도 해야함)
    @Query("SELECT ac FROM Accom AS ac WHERE (ac.x BETWEEN :xStart AND :xEnd) AND (ac.y BETWEEN :yStart AND :yEnd)")
    List<Accom> selectMiddle(
            @Param("xStart") double xStart,
            @Param("yStart") double yStart,
            @Param("xEnd") double xEnd,
            @Param("yEnd") double yEnd
    );

    @Query("SELECT ac FROM Accom AS ac WHERE (ac.locationFullAddress LIKE %:areaname% or ac.address LIKE %:areaname%) and ac.name LIKE %:word%")
    List<Accom> searchAccom(
            @Param("word") String word,
            @Param("areaname") String areaname
    );

    @Query("SELECT ac FROM Accom AS ac WHERE ac.locationFullAddress LIKE %:areaname% or ac.address LIKE %:areaname% ")
    List<Accom> searchAreaAccom(
            @Param("areaname") String areaname
    );
}
