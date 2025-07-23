package com.example.backend.member.service;

import com.example.backend.member.dto.MemberForm;
import com.example.backend.member.entity.Member;
import com.example.backend.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class MemberService {

    private final MemberRepository memberRepository;

//    public void add(MemberForm memberForm) {
//        Member member = new Member();
//        member.setId(memberForm.getId());
//        member.setPassword(memberForm.getPassword());
//        member.setEmail(memberForm.getEmail());
//        member.setName(memberForm.getName());
//        member.setNickName(memberForm.getNickName());
//        member.setInfo(memberForm.getInfo());
//        memberRepository.save(member);
//    }
}
