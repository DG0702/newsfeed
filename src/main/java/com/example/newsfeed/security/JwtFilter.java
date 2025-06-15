package com.example.newsfeed.security;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter implements Filter {
    private final JwtUtil jwtUtil;


    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain filterChain) throws IOException, ServletException {

        // HttpServlet으로 변경
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // URI 가져오기
        String requestURI = httpRequest.getRequestURI();

        String jwt = null;

        // 요청값에 헤더 안에 Authorization 값 가져오기
        String authorization = httpRequest.getHeader("Authorization");


        // 회원 가입 요청
        if(requestURI.startsWith("/auth/signup")){
            filterChain.doFilter(request,response);
            return;
        }

        // 요청 페이지로 이동할 경우 다음 필터로 이동 → 로그인 하여 토큰 발급 받기
        if(requestURI.startsWith("/auth/login")){
            filterChain.doFilter(request,response);
            return;
        }

        // JWT 토큰 존재 확인
        if(authorization == null || !authorization.startsWith("Bearer ")){
            log.info("JWT Token 필요");
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,"JWT 토큰이 필요합니다.");
            return;
        }

        // "Bearer " 빼고 가져옴
        jwt = authorization.substring(7);


        // JWT 토근 검증 (SecretKey 동일한지?, 만료시간이 지나지 않았는지)
        if(!jwtUtil.validateToken(jwt)){
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN); // 요청하였지만 권한이 없다
            httpResponse.getWriter().write("{\"error\" : \"Unauthorized\"}"); // JSON 형태의 답변
        }

        // 전용 API 아닌 일반 API 경우
        // (현재 권한이 없기 때문에 모든 API : 일반 API)
        filterChain.doFilter(request,response);
        
    }
}
