package com.securitytest.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userSeq;
    private String userId;
    private String username;
    private String password;
    private String role;
    private String email;
    // OAuth를 위해 구성한 추가 필드 2개
    private String provider;
    private String providerId;

}
