package com.example.backend.member.controller;

import com.example.backend.member.dto.*;
import com.example.backend.member.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/member")
public class MemberController {

    private final MemberService memberService;

    @PostMapping("logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        // 무상태 JWT 설정에서 백엔드에서의 로그아웃은 일반적으로 다음을 포함합니다:
        // 1. 클라이언트 측에서 JWT를 무효화 (스토리지에서 제거).
        // 2. (선택 사항) 토큰 블랙리스트/취소 메커니즘이 있다면 토큰을 추가합니다.
        // 간단한 JWT 설정의 경우, 클라이언트에서 토큰을 제거하는 것으로 충분합니다.
        // 스프링 시큐리티의 LogoutFilter는 세션 기반 보안의 세션 무효화를 처리할 수 있지만,
        // 무상태 JWT의 경우, 주로 클라이언트 측 토큰 제거에 의존합니다.
        // 이 엔드포인트는 단순히 로그아웃을 확인하거나 필요한 경우 보안 컨텍스트를 지울 수 있습니다.
        SecurityContextHolder.clearContext(); // 스프링 시큐리티 컨텍스트 지우기
        return ResponseEntity.ok().body(
                Map.of("message",
                        Map.of("type", "success",
                                "text", "로그아웃 되었습니다.")));
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody MemberLoginForm loginForm) {
//        System.out.println(loginForm);
        try {
            String token = memberService.getToken(loginForm);
            return ResponseEntity.ok().body(
                    Map.of("token", token,
                            "message",
                            Map.of("type", "success",
                                    "text", "로그인 되었습니다.")));
        } catch (Exception e) {
            e.printStackTrace();
            String message = e.getMessage();
            return ResponseEntity.status(401).body(
                    Map.of("message",
                            Map.of("type", "error",
                                    "text", message)));
        }

    }

    @PutMapping("changePassword")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordForm data,
                                            Authentication authentication) {
        if (!authentication.getName().equals(data.getEmail())) {
            return ResponseEntity.status(403).build();
        }

        try {
            memberService.changePassword(data);
        } catch (Exception e) {
            e.printStackTrace();
            String message = e.getMessage();
            return ResponseEntity.status(403).body(
                    Map.of("message",
                            Map.of("type", "error",
                                    "text", message)));
        }

        return ResponseEntity.ok().body(
                Map.of("message",
                        Map.of("type", "success",
                                "text", "암호가 변경되었습니다.")));
    }

    @PutMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> update(@ModelAttribute MemberForm memberForm,
                                    @RequestPart(value = "profileFiles", required = false) List<MultipartFile> profileFiles,
                                    @RequestParam(value = "deleteProfileFileNames", required = false) List<String> deleteProfileFileNames,
                                    Authentication authentication) {

        if (!authentication.getName().equals(memberForm.getEmail())) {
            return ResponseEntity.status(403).build();
        }
//        MemberForm form = new MemberForm();
//        form.setFiles(profileFiles); // 새로 추가된 파일

        try {
            memberService.update(memberForm, profileFiles, deleteProfileFileNames);

        } catch (Exception e) {
            e.printStackTrace();
            String message = e.getMessage();
            return ResponseEntity.status(403).body(
                    Map.of("message",
                            Map.of("type", "error",
                                    "text", message)));
        }
        return ResponseEntity.ok().body(
                Map.of("message",
                        Map.of("type", "success",
                                "text", "회원 정보가 수정되었습니다.")));
    }

    @DeleteMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> deleteMember(@RequestBody MemberForm memberForm,
                                          Authentication authentication) {
        if (!authentication.getName().equals(memberForm.getEmail())) {
            return ResponseEntity.status(403).build();
        }

        try {
            memberService.delete(memberForm);
        } catch (Exception e) {
            e.printStackTrace();
            String message = e.getMessage();
            return ResponseEntity.status(403).body(
                    Map.of("message",
                            Map.of("type", "error",
                                    "text", message)));
        }
        return ResponseEntity.ok().body(
                Map.of("message",
                        Map.of("type", "success",
                                "text", "회원 정보가 삭제되었습니다.")));
    }

    @GetMapping(params = "email")
    @PreAuthorize("isAuthenticated() or hasAuthority('SCOPE_admin')")
    public ResponseEntity<?> getMember(String email, Authentication authentication) {
        if (authentication.getName().equals(email) ||
                authentication.getAuthorities()
                        .contains(new SimpleGrantedAuthority("SCOPE_admin"))) {
            return ResponseEntity.ok().body(memberService.get(email));
        } else {
            return ResponseEntity.status(403).build();
        }
    }

    @GetMapping("list")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public List<MemberListInfo> list() {
        return memberService.list();
    }

    @PostMapping("add")
    public ResponseEntity<?> add(@ModelAttribute MemberForm memberForm) {
//        System.out.println("memberForm = " + memberForm);
        try {
            memberService.add(memberForm);
        } catch (Exception e) {
            e.printStackTrace();
            String message = e.getMessage();
            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            Map.of("type", "error",
                                    "text", message)));
        }

        return ResponseEntity.ok().body(
                Map.of("message",
                        Map.of("type", "success",
                                "text", "회원 가입 되었습니다."))
        );
    }

}