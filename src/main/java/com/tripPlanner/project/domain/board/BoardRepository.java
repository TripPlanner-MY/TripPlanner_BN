package com.tripPlanner.project.domain.board;

import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BoardRepository extends JpaRepository<Planner, Integer> {

    Page<Planner> findByIsPublicTrue(Pageable pageable); // 공개된 플래너만 페이징 처리
}
