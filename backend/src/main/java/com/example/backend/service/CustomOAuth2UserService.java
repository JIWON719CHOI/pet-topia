// src/main/java/com/example/backend/service/CustomOAuth2UserService.java

package com.example.backend.service;

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

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        logger.info("OAuth2User loaded: {}", oauth2User.getAttributes());

        final String registrationId = userRequest.getClientRegistration().getRegistrationId(); // <-- final 추가
        final Map<String, Object> attributes = oauth2User.getAttributes(); // <-- final 추가

        // 람다에서 참조될 변수들은 여기서 final 또는 effectively final로 만들어야 합니다.
        // 여기서는 바로 값을 할당하여 final 또는 effectively final 상태로 만듭니다.
        final String email;
        final String name;
        final String providerId;

        if ("google".equals(registrationId)) {
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            providerId = (String) attributes.get("sub");
        } else {
            // 다른 OAuth 제공자를 처리하지 않는다면 예외 발생
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
                    return new CustomOAuth2User(member, attributes); // final attributes 사용
                })
                .orElseGet(() -> {
                    logger.info("New member: Registering email {}", email); // final email 사용
                    Member newMember = new Member();
                    newMember.setEmail(email); // final email 사용
                    newMember.setPassword(null);
                    newMember.setNickName(name != null ? name : UUID.randomUUID().toString().substring(0, 8)); // final name 사용
                    newMember.setInfo("OAuth2 user via " + registrationId); // final registrationId 사용
                    newMember.setProvider(registrationId); // final registrationId 사용
                    newMember.setProviderId(providerId); // final providerId 사용
                    newMember.setRole(Member.Role.USER);
                    memberRepository.save(newMember);
                    logger.info("New member saved: {}", newMember.getEmail());
                    return new CustomOAuth2User(newMember, attributes); // final attributes 사용
                });
    }
}