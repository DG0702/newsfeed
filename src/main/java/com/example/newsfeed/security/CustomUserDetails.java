package com.example.newsfeed.security;

import com.example.newsfeed.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;


@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    // 유저의 권한 목록을 반환 (예 : ROLE_USER, ROLE_ADMIN)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    // 인증에 사용할 유저의 비밀번호 반환 (암호화된 상태)
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 인증에 사용할 유저의 고유 식별자 (보통 username 대신 email 사용)
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    // 계정 만료 여부 : true → 만료 안됨
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠김 여부 : true → 잠기지 않음
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    // 비밀번호 만료 여부 true → 만료 안됨
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 여부 : true → 활성화된 계정
    @Override
    public boolean isEnabled() {
        return true;
    }

    public User getUser() {
        return user;
    }


}
