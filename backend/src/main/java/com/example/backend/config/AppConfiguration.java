package com.example.backend.config;

import com.example.backend.auth.repository.AuthRepository;
import com.example.backend.member.entity.Member;
import com.example.backend.member.entity.Member.Role;
import com.example.backend.member.repository.MemberRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
@RequiredArgsConstructor
public class AppConfiguration {

    private final MemberRepository memberRepository;
    private final AuthRepository authRepository;

    @Value("classpath:secret/public.pem")
    private RSAPublicKey publicKey;

    @Value("classpath:secret/private.pem")
    private RSAPrivateKey privateKey;

    @Value("${aws.access.key}")
    private String accessKey;

    @Value("${aws.secret.key}")
    private String secretKey;

    @Bean
    public S3Client s3Client() {
        AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);
        AwsCredentialsProvider provider = StaticCredentialsProvider.create(credentials);

        S3Client s3Client = S3Client.builder()
                .region(Region.AP_NORTHEAST_2)
                .credentialsProvider(provider)
                .build();

        return s3Client;

    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.csrf(c -> c.disable());
//        http.oauth2ResourceServer(c -> c.jwt(Customizer.withDefaults()));

//        return http.build();
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable) // 실제 앱에서는 CORS를 제대로 설정하는 것을 고려하세요
                .authorizeHttpRequests(auth -> auth
                        // 로그인 및 추가, OAuth2 엔드포인트 접근 허용
                        .requestMatchers("/api/member/login", "/api/member/add", "/oauth2/**", "/login/oauth2/code/**").permitAll()
                        // 모든 /api/** 경로를 인증없이 접근 허용
                        .requestMatchers("/api/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(this.oauth2UserService())
                        )
                        .defaultSuccessUrl("http://localhost:5173/", true) // OAuth2 로그인 성공 후 홈페이지로 리디렉션
                        .failureUrl("/login?error") // 실패 시 로그인 페이지로 리디렉션
                )
                // TODO 다시 이거로 바꿔야함
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 확인용
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(logout -> logout
                        .logoutUrl("/api/member/logout") // 로그아웃 URL 정의
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(200); // 또는 204 No Content
                            response.getWriter().write("Logged out successfully"); // 메시지 전송
                            response.getWriter().flush();
                        })
                        .permitAll()
                );
        // TODO 다시 살려야함
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public UserDetailsService userDetailsService(MemberRepository memberRepository,
                                                 AuthRepository authRepository) {
        return email -> {
            Member member = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));
            // Member의 기본 Role (예: USER)을 권한으로 사용하거나
            // authRepository를 통해 추가적인 권한을 조회할 수 있습니다.
            List<String> roles = authRepository.findAuthNamesByMemberId(member.getId());
            if (roles.isEmpty()) {
                // 특정 권한이 없다면 기본 역할(Role.USER)을 부여
                roles = Collections.singletonList(member.getRole().name());
            }

            return new CustomUserDetails(member, roles); // CustomUserDetails 객체 반환
        };
    }

    @Bean
    public ProviderManager authenticationManager(UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return new ProviderManager(authenticationProvider);
    }

    // 구글 OAuth2UserService를 커스터마이징하여 사용자 등록/로그인 처리
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return (userRequest) -> {
            OAuth2User oauth2User = delegate.loadUser(userRequest);

            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name"); // 또는 "login" (제공자에 따라 다름)
            String provider = userRequest.getClientRegistration().getRegistrationId(); // 예: "google"
            String providerId = oauth2User.getName(); // OAuth2 제공자의 고유 ID

            // 사용자 데이터베이스에 이미 존재하는지 확인
            return memberRepository.findByEmail(email)
                    .map(member -> {
                        // 사용자가 존재하면 필요에 따라 정보 업데이트 (예: 최종 로그인, 이름)
                        // 또한, 기존 이메일로 첫 OAuth 로그인인 경우 제공자와 providerId가 올바르게 설정되었는지 확인
                        if (member.getProvider() == null || member.getProviderId() == null) {
                            member.setProvider(provider);
                            member.setProviderId(providerId);
                            memberRepository.save(member);
                        }
                        return new CustomOAuth2User(member, oauth2User.getAttributes());
                    })
                    .orElseGet(() -> {
                        // 사용자가 존재하지 않으면 등록
                        Member newMember = new Member();
                        newMember.setEmail(email);
                        // OAuth2의 경우, 보통 비밀번호를 저장하지 않거나 임의의 비밀번호를 생성합니다.
                        // 나중에 비밀번호 기반 로그인을 허용할 예정이라면 플레이스홀더나 null을 설정할 수 있습니다.
                        newMember.setPassword(null); // OAuth2 사용자는 비밀번호 없음
                        newMember.setNickName(name != null ? name : UUID.randomUUID().toString().substring(0, 8)); // 이름 사용 또는 임의 닉네임 생성
                        newMember.setInfo("OAuth2 user via " + provider);
                        newMember.setProvider(provider);
                        newMember.setProviderId(providerId);
                        newMember.setRole(Role.USER); // 기본 역할
                        memberRepository.save(newMember);
                        return new CustomOAuth2User(newMember, oauth2User.getAttributes());
                    });
        };
    }
}