package com.tripPlanner.project.domain.signin.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.tripPlanner.project.domain.destination.Like;
import com.tripPlanner.project.domain.makePlanner.entity.Planner;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.util.List;



@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Table(name = "tbl_user")
public class UserEntity {

    @Id
    @Column(name = "userid", length = 255)
    @JsonManagedReference
    private String userid;

    @Column(name = "img", length = 1024)
    private String img;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "gender", nullable = false)
    private String gender;

    @Column(name = "role", nullable = false)
    private String role;

    @Column(name = "birth" , length = 8)
    private int birth;

    private String provider;

    private String providerId;

    @OneToMany(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @OnDelete(action = OnDeleteAction.CASCADE) // 외래 키 제약 조건에 따른 삭제
    @JsonBackReference // Planner와의 순환 참조 방지
    private List<Planner> planners; // User와 연결된 Planner 목록

    @OneToMany(mappedBy = "userId", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonBackReference // Like와의 순환 참조 방지
    private List<Like> likes;

    @PrePersist // 엔티티 저장 직전에 호출
    public void prePersist() {
        this.role = this.role == null ? "ROLE_USER" : this.role;
    }

}
