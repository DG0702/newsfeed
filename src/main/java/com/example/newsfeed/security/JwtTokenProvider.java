package com.example.newsfeed.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Slf4j
public class JwtTokenProvider {

    // 접두사 "Bearer"
    public static final String BEARER_PREMIX = "Bearer ";
    
    // 비밀키 → 더 복잡한 키 사용 권장 (최소256비트(32바이트)이상의 길이 요구)
    @Value("mySuperSecureSecretKeyThatIsAtLeast32Chars  ")
    private String SECRET_KEY;

    // 만료시간 설정
    @Value("3600000")
    private long expiration;
    
    // SecretKey 캐싱하여 재사용
    private SecretKey secretKey;

    // 초기화 시점에 SecretKey 생성
    @PostConstruct
    public void init(){
        this.secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    // SecretKey 재사용
    private SecretKey getSecretKey(){
        return secretKey;
    }



    // 토근 생성 메서드
    public String createToken(Authentication authentication) {

        String userEmail = authentication.getName();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        String token = Jwts.builder() 
                // Jwts : 유틸리티 클래스 → JWT 생성, 파싱, 검증하는 작업을 도움
                
                // 파싱 = JWT 문자열을 해체하고, 서명 검증 후 페이로드 데이터를 추출하는 과정

                .setSubject(userEmail) // 토큰 주체 (유저 식별값)
                .setIssuedAt(now) // 발행시간
                .setExpiration(expiryDate) // 만료시간
                .signWith(getSecretKey(), SignatureAlgorithm.HS256) // 서명 알고리즘과 키
                .compact(); // 실제 JWT 문자열 형식으로 최종 변환해주는 메서드

        return BEARER_PREMIX + token; // "Bearer" 접두사 붙이기
    }

    // 토근 검증 메서드
    public boolean validateToken(String token){
        try {
            Jwts.parserBuilder()
                    // JWT 토큰을 검증할 때 사용할 서명 키를 설정하는 메서드 → 문자열 비밀키를 바이트 배열로 변경 후 알고리즘에 맞는 키 객체로 변경
                    .setSigningKey(getSecretKey())
                    .build() // 파서 객체 생성하는 메서드
                    .parseClaimsJws(token); // JWT 토큰을 파서 객체로 토큰 파싱 후 검증하는 메서드
            return true;
        } catch (Exception e) {
            log.warn("Invalid JWT : {}", e.getMessage() );
            return false; // 토근이 유효하지 않을 경우 예외 발생
        }
    }
    
    //토근에서 사용자 정보 추출
    public String getUserEmailFromToken(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // HTTP Header "Authorization" 필드 안에 "Bearer<토큰>" 형태 → JWT 토큰 형태로 변경
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // "Bearer" 이후 문자열만 반환 → "Bearer" 제거
        }
        return null;
    }
    
    public Long getExpiration(String token){
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey) // 비밀키 사용
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();
            return expiration.getTime() - System.currentTimeMillis(); // 남은 시간 (ms)
        }catch (JwtException | IllegalArgumentException e){
            throw new RuntimeException("유효하지 않은 JWT 토큰입니다");
        }
    }


}
