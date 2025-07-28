package com.example.backend.config;

import com.example.backend.auth.repository.AuthRepository;
import com.example.backend.jwt.TokenProvider;
import com.example.backend.member.entity.Member;
import com.example.backend.member.entity.Member.Role;
import com.example.backend.member.repository.MemberRepository;
import com.example.backend.service.CustomOAuth2UserService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor; // 일단 그대로 둡니다.
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
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
public class AppConfiguration { // @RequiredArgsConstructor 제거 또는 아래에서 필요한 것만 생성자로 주입

    private final MemberRepository memberRepository;
    private final AuthRepository authRepository;
    private final CustomOAuth2UserService customOAuth2UserService;
    // private final TokenProvider tokenProvider; // <-- 이 줄을 제거하세요!

    // @RequiredArgsConstructor를 사용하지 않으므로, 필요한 필드만 직접 생성자로 주입받습니다.
    public AppConfiguration(MemberRepository memberRepository, AuthRepository authRepository, CustomOAuth2UserService customOAuth2UserService) {
        this.memberRepository = memberRepository;
        this.authRepository = authRepository;
        this.customOAuth2UserService = customOAuth2UserService;
    }

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
    public SecurityFilterChain securityFilterChain(HttpSecurity http, TokenProvider tokenProvider) throws Exception {
        // TokenProvider를 메서드 파라미터로 주입받습니다.
        // 이렇게 하면 Spring이 TokenProvider 빈을 먼저 생성하고,
        // 그 다음에 SecurityFilterChain 빈을 생성할 때 TokenProvider를 주입할 수 있습니다.
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        // 로그인 및 추가, OAuth2 엔드포인트 접근 허용
                        .requestMatchers("/api/member/login", "/api/member/add", "/oauth2/**", "/login/oauth2/code/**").permitAll()
                        // 모든 /api/** 경로를 인증없이 접근 허용
                        // TODO: 실제 배포 시에는 인증 필요한 API는 이 permitAll()에서 제외하고 .authenticated()로 보호해야 합니다.
                        .requestMatchers("/api/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .successHandler((request, response, authentication) -> {
                            CustomOAuth2User principal = (CustomOAuth2User) authentication.getPrincipal();
                            String token = tokenProvider.generateToken(authentication); // 주입받은 tokenProvider 사용
                            String redirectUrl = "http://localhost:5173/?token=" + token; // 프론트엔드로 JWT 토큰 전달
                            response.sendRedirect(redirectUrl);
                        })
                        .failureUrl("/login?error")
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
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
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder()))); // JWT 리소스 서버 활성화

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
            List<String> roles = authRepository.findAuthNamesByMemberId(member.getId());
            if (roles.isEmpty()) {
                roles = Collections.singletonList(member.getRole().name());
            }

            return new CustomUserDetails(member, roles);
        };
    }

    @Bean
    public ProviderManager authenticationManager(UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}