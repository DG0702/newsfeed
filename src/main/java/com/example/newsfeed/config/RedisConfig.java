package com.example.newsfeed.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

@Configuration
public class RedisConfig {

    @Bean
    // RedisConnectionFactory : Redis 서버와 연결, 생성, 관리하는 인터페이스
    public RedisConnectionFactory redisConnectionFactory() {
        // LettuceConnectionFactory : RedisConnectionFactory 구현체 → Lettuce 사용
        // Lettuce : Java Application(클라이언트)에서 Redis 서버와 연결을 도와주는 라이브러리
        return new LettuceConnectionFactory();
    }

    @Bean
    // Redis 데이터를 저장하거나 조회할 때 사용하는 "템플릿 객체"를 생성하는 메서드
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory){
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        // factory 매개변수는  redisConnectionFactory 메서드에서 생성한 객체를 받는다 → @Bean(Spring)에 의해 자동으로 주입됨
        template.setConnectionFactory(factory);
        return template;
    }


}
