package com.example.newsfeed.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    // JWT 토큰의 접두사
    public static final String BEARER_PREFIX = "Bearer ";

    // JWT 만료시간 (밀리초 단위)
    @Value("3600000")
    private long TokenExpirationTime;

    // JWT 서명 알고리즘
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    // Secret Key (비밀키)
    @Value("mySuperSecureSecretKeyThatIsAtLeast32CharMoreWrite")
    private String secretKey;

    // 실제 서명에 사용되는 Key 객체
    private Key key;

    /**
     * Key 초기화
     * - 애플리케이션 시작 시 비밀키를 Base64로 디코딩하여 Key 객체에 초기화
     */
    @PostConstruct
    public void init(){
        byte [] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    /**
     * JWT 토큰 생성 메서드
     * @param userName 사용자 이름
     * @return 생성된 JWT 토큰
     */
    
    public String generateToken(String userName){
        Date now = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(userName) // 사용자 식별자 (ID)
                        .setIssuedAt(now) // 토큰 발급 시간
                        .setExpiration(new Date(now.getTime() + TokenExpirationTime)) // 토큰 만료 시간
                        .signWith(key, signatureAlgorithm) // 비밀키, 알고리즘 설정
                        .compact(); // JWT 토큰 생성
    }


    /**
     * JWT 토큰 검증 메서드
     * @param token 검증할 JWT Token
     * @return 토큰의 유효성 여부 (true 유효, false 유효하지 않음)
     */
    public boolean validateToken(String token){
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key) // 서명 검증에 사용할 비밀키 설정
                    .build()
                    .parseClaimsJws(token); // 토큰 파싱 및 서명 검증
            return true;
        } catch (SecurityException | MalformedJwtException e){
            log.error("Invalid JWT signature, 유효하지 않은 JWT 서명입니다.");
        } catch (ExpiredJwtException e){
            log.error("Expired JWT Token , 만료된 JWT Token 입니다");
        } catch (UnsupportedJwtException e){
            log.error("Unsupported JWT Token , 지원되지 않은 JWT 토큰입니다.");
        } catch (IllegalArgumentException e){
            log.error("JWT claims is empty , 잘못된 JWT Token 입니다.");
        }
        return false;
    }



}
