package com.example.newsfeed.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        // 1. 요청 헤더에서 JWT 호출
        String token = resolveToken(request);
        
        // 2. 토큰 유효성 검사
        if(token != null && jwtTokenProvider.validateToken(token)) {
            
            // 3. 토큰에서 사용자 정보 추출
            String userEmail = jwtTokenProvider.getUserEmailFromToken(token);
            
            // 4. userDetails 조회 및 인증 객체 생성
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // 5. SecurityContext 안에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // 6. 다음 필터로 전달
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
