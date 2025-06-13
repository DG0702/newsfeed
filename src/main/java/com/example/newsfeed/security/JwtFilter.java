package com.example.newsfeed.security;


import com.example.newsfeed.auth.service.TokenBlacklistService;
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
    private final TokenBlacklistService tokenBlacklistService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {

        // try catch 문을 사용해야 security에서 401 에러를 날림 
        // 없을 경우 단순 서버 오류인 500 에러 날림
        try {
            // 1. 요청 헤더에서 JWT 호출
            String token = jwtTokenProvider.resolveToken(request);

            // 2. 토큰 유효성 검사 (토큰이 존재하고 && 토큰이 유효하고 && 현재 인증 객체가 비어 있다면)
            if(StringUtils.hasText(token) &&
                    jwtTokenProvider.validateToken(token) &&
                    SecurityContextHolder.getContext().getAuthentication() == null
            ) {

                // 3. 로그아웃 확인 (블랙리스트로 등록된 토큰인지 확인)
                if(tokenBlacklistService.isTokenBlacklisted(token)){
                    log.warn("블랙리스트 토큰 접근 시도 {}", token);
                    throw new SecurityException("이미 로그아웃 된 토큰입니다.");
                }

                // 4. 토큰에서 사용자 정보 추출
                String userEmail = jwtTokenProvider.getUserEmailFromToken(token);

                // 5. 사용자 정보 로드 (userDetails 조회 및 인증 객체 생성)
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);

                // 6.인증 객체 생성 (추가 정보 포함)
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());


                // 7. 인증 객체 저장 (SecurityContext 안에 인증 정보 저장)
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT authentication successful for user {}",userEmail);
            }
        }catch (SecurityException ex){
            log.error("JWT 인증 실패 (security) : {}",ex.getMessage() );
            SecurityContextHolder.clearContext();
            response.sendError((HttpServletResponse.SC_UNAUTHORIZED),ex.getMessage());
        }
        catch (Exception e) {
            log.error("JWT authentication failed {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        // 8. 다음 필터로 전달
        filterChain.doFilter(request, response);
        
    }

    


}
