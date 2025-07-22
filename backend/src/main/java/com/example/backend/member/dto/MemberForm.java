package com.example.backend.member.dto;

import lombok.Data;

@Data
public class MemberForm {
    private String id;
    private String password;
    private String email;
    private String name;
    private String nickName;
    private String info;
}
