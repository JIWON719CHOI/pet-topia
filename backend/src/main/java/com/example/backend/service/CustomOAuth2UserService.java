// src/main/java/com/example/backend/config/CustomOAuth2UserService.java
package com.example.backend.service; // 혹은 적절한 패키지

import com.example.backend.config.CustomOAuth2User;
import com.example.backend.member.entity.Member;
import com.example.backend.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service // 이 어노테이션이 있다면 AppConfiguration에서 @Bean으로 직접 등록할 필요 없습니다.
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        logger.info("OAuth2User loaded: {}", oauth2User.getAttributes());

        final String registrationId = userRequest.getClientRegistration().getRegistrationId(); // final
        final Map<String, Object> attributes = oauth2User.getAttributes(); // final

        // 이 변수들은 람다 내에서 사용되므로, final 또는 effectively final 이어야 합니다.
        // if-else 분기 전에 한 번만 할당되도록 보장합니다.
        final String email;
        final String name;
        final String providerId;

        if ("google".equals(registrationId)) {
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            providerId = (String) attributes.get("sub");
        } else {
            throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }
        logger.info("Provider: {}, Email: {}, Name: {}, ProviderId: {}", registrationId, email, name, providerId);

        return memberRepository.findByEmail(email)
                .map(member -> {
                    logger.info("Existing member found: {}", member.getEmail());
                    if (member.getProvider() == null || member.getProviderId() == null) {
                        member.setProvider(registrationId); // final registrationId 사용
                        member.setProviderId(providerId); // final providerId 사용
                        memberRepository.save(member);
                        logger.info("Updated existing member: {}", member.getEmail());
                    }
                    return new CustomOAuth2User(member, attributes);
                })
                .orElseGet(() -> {
                    logger.info("New member: Registering email {}", email);
                    Member newMember = new Member();
                    newMember.setEmail(email);
                    newMember.setPassword(null);
                    newMember.setNickName(name != null ? name : UUID.randomUUID().toString().substring(0, 8));
                    newMember.setInfo("OAuth2 user via " + registrationId);
                    newMember.setProvider(registrationId);
                    newMember.setProviderId(providerId);
                    newMember.setRole(Member.Role.USER); // Member.Role 임포트 확인
                    memberRepository.save(newMember);
                    logger.info("New member saved: {}", newMember.getEmail());
                    return new CustomOAuth2User(newMember, attributes);
                });
    }
}