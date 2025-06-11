package com.example.newsfeed.security;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {

        // try catch 문을 사용해야 security에서 401 에러를 날림 
        // 없을 경우 단순 서버 오류인 500 에러 날림
        try {
            // 1. 요청 헤더에서 JWT 호출
            String token = resolveToken(request);

            // 2. 토큰 유효성 검사 (토큰이 존재하고 && 토큰이 유효하고 && 현재 인증 객체가 비어 있다면)
            if(StringUtils.hasText(token) &&
                    jwtTokenProvider.validateToken(token) &&
                    SecurityContextHolder.getContext().getAuthentication() == null
            ) {

                // 3. 토큰에서 사용자 정보 추출
                String userEmail = jwtTokenProvider.getUserEmailFromToken(token);

                // 4. userDetails 조회 및 인증 객체 생성
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);

                // 5.인증 토큰 생성 (추가 정보 포함)
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());


                // 6. SecurityContext 안에 인증 정보 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT authentication successful for user {}",userEmail);
            }
        } catch (Exception e) {
            log.error("JWT authentication failed {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        // 7. 다음 필터로 전달
        filterChain.doFilter(request, response);
        
    }

    

    // HTTP Header "Authorization" 필드 안에 "Bearer<토큰>" 형태 → JWT 토큰 형태로 변경
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // "Bearer" 이후 문자열만 반환
        }
        return null;
    }
}
