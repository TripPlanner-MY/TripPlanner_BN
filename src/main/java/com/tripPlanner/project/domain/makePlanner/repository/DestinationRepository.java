package com.tripPlanner.project.domain.makePlanner.repository;

import com.tripPlanner.project.domain.makePlanner.entity.Destination;
import com.tripPlanner.project.domain.makePlanner.entity.DestinationID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DestinationRepository extends JpaRepository<Destination, DestinationID> {

    // 플래너 ID의 첫번째 날, 첫번째 여행지에 대한 이미지 가져오기
    @Query("SELECT d FROM Destination d WHERE d.planner.plannerID = :plannerID AND d.destinationID.day = :day AND d.destinationID.dayOrder = :dayOrder")
    Destination findFirstDestinationForPlanner(
            @Param("plannerID") int plannerID,
            @Param("day") int day,
            @Param("dayOrder") int dayOrder);

    // 플래너 ID로 해당 플래너의 destination들 조회
    List<Destination> findByPlanner_PlannerID(int plannerID);

}
