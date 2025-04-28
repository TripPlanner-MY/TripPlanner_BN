package com.tripPlanner.project.domain.destination;


import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LikeRepository extends JpaRepository<Like, Planner> {

    boolean existsByPlannerIdAndUserId(Planner plannerID, UserEntity userId);

    void deleteByPlannerIdAndUserId(Planner plannerID, UserEntity userId);

    int countByPlannerId(Planner plannerID);

    List<Like> findByUserId(UserEntity userId);
}
