// src/main/java/com/example/backend/config/CustomOAuth2User.java
package com.example.backend.config;

import com.example.backend.member.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private Member member;
    private Map<String, Object> attributes;

    public CustomOAuth2User(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + member.getRole().name()));
    }

    @Override
    public String getName() {
        // OAuth2 제공자로부터 사용자의 고유 식별자, 일반적으로 'sub'를 반환합니다.
        return member.getProviderId() != null ? member.getProviderId() : member.getEmail();
    }

    public Member getMember() {
        return member;
    }

    public String getEmail() {
        return member.getEmail();
    }
}