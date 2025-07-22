package com.example.backend.member.controller;

import com.example.backend.member.dto.MemberForm;
import com.example.backend.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/member")
public class MemberController {

    private final MemberService memberService;

//    @PostMapping("add")
//    public void addMember(MemberForm memberForm) {
//        System.out.println("MemberController.addMember");
//        System.out.println(memberForm);
////        memberService.add(memberForm);
//    }
}
