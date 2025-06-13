package com.example.newsfeed.security;


import com.example.newsfeed.auth.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, TokenBlacklistService tokenBlacklistService) throws Exception {
        http
                // CSRF 보호 비활성화 (JWT 사용 시에는 보통 필요 없음)
                .csrf(csrf -> csrf.disable())

                // 기본 HTTP 인증 비활성화
                .httpBasic(httpBasic -> httpBasic.disable())

                // 폼 로그인 비활성화 (JWT 인증 방식 사용하기 때문)
                .formLogin(formLogin -> formLogin.disable())

                // 세션 사용 안함 : STATELESS 설정 (JWT 사용하기 때문에 서버가 세션을 저장하지 않음)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // URL 경로별 접근 권한 설정
                .authorizeHttpRequests(auth ->
                        // /auth/** 경로는 인증 없이 접근 가능
                        auth.requestMatchers("/auth/**").permitAll()
                        
                        // 그 외 모든 요청은 인증(로그인) 필요        
                        .anyRequest().authenticated())

                // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 등록 → JWT 필터로 먼저 인증하여 뒤에 인증을 하지 않도록 설정
                .addFilterBefore(new JwtFilter(
                        jwtTokenProvider,customUserDetailsService,tokenBlacklistService),
                        UsernamePasswordAuthenticationFilter.class);
        
        // 최종적으로 SecurityFilterChain 객체 반환
        return http.build();
    }
}
