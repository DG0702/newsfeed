package com.example.newsfeed.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;


import java.util.Date;

public class JwtTokenProvider {
    
    // 비밀키 → 더 복잡한 키 사용 권장
    private final String SECRET_KEY = "mySecretKey12345";

    // 토근 생성 메서드
    public String createToken(String userEmail) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 1000 * 60 * 60);
        
        return Jwts.builder() 
                // Jwts : 유틸리티 클래스 → JWT 생성, 파싱, 검증하는 작업을 도움
                
                // 파싱 = JWT 문자열을 해체하고, 서명 검증 후 페이로드 데이터를 추출하는 과정

                .setSubject(userEmail) // 토큰 주체 (유저 식별값)
                .setIssuedAt(now) // 발행시간
                .setExpiration(expiryDate) // 만료시간
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()), SignatureAlgorithm.HS256) // 서명 알고리즘과 키
                .compact(); // 실제 JWT 문자열 형식으로 최종 변환해주는 메서드
    }

    // 토근 검증 메서드
    public boolean validateToken(String token){
        try {
            Jwts.parserBuilder()
                    // JWT 토큰을 검증할 때 사용할 서명 키를 설정하는 메서드 → 문자열 비밀키를 바이트 배열로 변경 후 알고리즘에 맞는 키 객체로 변경
                    .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes())) 
                    .build() // 파서 객체 생성하는 메서드
                    .parseClaimsJws(token); // JWT 토큰을 파서 객체로 토큰 파싱 후 검증하는 메서드
            return true;
        } catch (Exception e) {
            return false; // 토근이 유효하지 않을 경우 예외 발생
        }
    }
    
    //토근에서 사용자 식별 정보 추출
    public String getUserEmailFromToken(String token){
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }


}
