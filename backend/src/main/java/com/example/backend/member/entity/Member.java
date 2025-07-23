package com.example.backend.member.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "member1")
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String id;

    @Column(nullable = false, unique = true)
    private String username; // 이메일

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name; // 본명

    @Column(nullable = false)
    private String nickName; // 닉네임

    private String info;

    @Column(insertable = false, updatable = false)
    private LocalDateTime insertedAt; // 가입일

    @Column(nullable = false)
    private String social_type;

    // 선택사항
    @Column(nullable = false)
    private String social_id;

    // 권한?
//    private Set<Role> roles = new HashSett<>();


}
