package com.example.backend.member.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "member1")
public class Member {
    @Id
    private String id;

    private String password;
    private String email;
    private String name;
    private String nickName;
    private String info;

    @Column(insertable = false, updatable = false)
    private LocalDateTime insertedAt;
}
