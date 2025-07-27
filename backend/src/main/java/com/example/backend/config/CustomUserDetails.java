package com.example.backend.config;

import com.example.backend.member.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private Member member;
    // 필요하다면 추가적인 권한 목록 (예: Auth 엔티티에서 가져온 권한 이름들)
    private List<String> roles; // 예를 들어 "ROLE_USER", "ROLE_ADMIN"

    public CustomUserDetails(Member member, List<String> roles) {
        this.member = member;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Member의 Role 필드에서 권한 생성
        // 예: member.getRole()이 Member.Role.USER라면 "ROLE_USER" 권한을 반환
        // 또는 roles 리스트를 사용 (이것이 더 유연합니다)
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
        // 만약 Member의 Role Enum만 사용한다면:
        // return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + member.getRole().name()));
    }

    @Override
    public String getPassword() {
        // Member 엔티티의 비밀번호 반환
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        // Spring Security에서 사용자 이름을 나타내며, 여기서는 이메일 사용
        return member.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        // 계정 만료 여부. 여기서는 항상 true로 설정 (필요시 DB 필드 추가하여 관리)
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // 계정 잠금 여부. 여기서는 항상 true로 설정 (필요시 DB 필드 추가하여 관리)
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // 자격 증명(비밀번호) 만료 여부. 여기서는 항상 true로 설정 (필요시 DB 필드 추가하여 관리)
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 계정 활성화 여부. 여기서는 항상 true로 설정 (필요시 DB 필드 추가하여 관리)
        return true;
    }

    // Member 객체에 접근하기 위한 getter (필요시)
    public Member getMember() {
        return member;
    }
}