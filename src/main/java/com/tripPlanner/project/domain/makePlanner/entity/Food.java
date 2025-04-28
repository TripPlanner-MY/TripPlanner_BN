package com.tripPlanner.project.domain.makePlanner.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name="tbl_food")
public class Food {
    @Id
    @Column(name="id")
    private String id;

    @Column(name="business_name")
    private String name;

    @Column(name="x_coordinate")
    private double x;

    @Column(name="y_coordinate")
    private double y;

    @Column(name="location_phone_number")
    private String locationPhoneNumber;

    @Column(name="location_postal_code")
    private String locationPostalCode;

    @Column(name="location_full_address")
    private String locationFullAddress;

    @Column(name="street_postal_code")
    private String streetPostalCode;

    @Column(name="street_full_address")
    private String address;

    @Column(name="business_category")
    private String category;

    @Column(name="image")
    private String image;
}
