//package com.tripPlanner.project.commons.entity;
//
//import com.tripPlanner.project.domain.destination.DestinationDto;
//import jakarta.persistence.*;
//import lombok.Getter;
//import lombok.NoArgsConstructor;
//
//@Entity
//@Getter
//@Table(name = "Destination")
//@NoArgsConstructor
//public class Destination {
//
//    @EmbeddedId
//    private DestinationID destinationID;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "plannerID", referencedColumnName = "plannerID", insertable = false, updatable = false)
//    private Planner planner; // Planner와의 관계 설정 (외래 키)
//
//    @Column(name = "name")
//    private String name; // 장소명 (nullable)
//
//    @Column(name = "x", nullable = false)
//    private double x; // 경도
//
//    @Column(name = "y", nullable = false)
//    private double y; // 위도
//
//    @Column(name = "address")
//    private String address; // 주소
//
//    @Column(name = "category")
//    private String category; // 카테고리
//
//    @Column(name = "image")
//    private String image; // 장소의 이미지 URL (구글 API사용)
//
//    public DestinationDto toDto() {
//        return new DestinationDto(
//                this.name,
//                this.x,
//                this.y,
//                this.address,
//                this.category,
//                this.image,
//                this.planner.getUser().getUsername(),  // Username만 포함
//                this.destinationID.getPlannerID(),
//                this.destinationID.getDay(),
//                this.destinationID.getDayOrder()
//        );
//    }
//}
