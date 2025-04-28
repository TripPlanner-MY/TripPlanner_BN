//package com.tripPlanner.project.commons.entity;
//
//import com.tripPlanner.project.domain.board.BoardDto;
//import jakarta.persistence.*;
//import lombok.*;
//
//import java.time.LocalDateTime;
//
//@Getter
//@NoArgsConstructor
//@Table(name = "Planner")
//@Entity
//@AllArgsConstructor
//@Builder
//public class Planner {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private int plannerID; // 여행 일정 ID
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "userid", nullable = false)
//    private UserEntity user; // 사용자
//
//    @Column(name = "plannerTitle", nullable = false)
//    private String plannerTitle;
//
//    @Column(name = "createAt", nullable = false, updatable = false)
//    private LocalDateTime createAt = LocalDateTime.now(); // 등록일자
//
//    @Column(name = "updateAt", nullable = false)
//    private LocalDateTime updateAt = LocalDateTime.now(); // 수정일자
//
//    @Column(name = "day", nullable = false)
//    private int day; // 여행 기간
//
//    @Column(name = "isPublic", nullable = false)
//    private boolean isPublic; // 공개 여부 (생성 시 선택)
//
//    @Column(name = "area", nullable = false)
//    private String area;
//
//    @Column(name = "description", nullable = false)
//    private String description;
//
//
//}
