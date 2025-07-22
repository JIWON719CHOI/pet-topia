package com.example.backend.member.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "member")
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
