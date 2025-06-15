package com.example.newsfeed.domain.user.service;

import com.example.newsfeed.auth.dto.LoginRequestDto;
import com.example.newsfeed.common.exception.PasswordMismatchException;
import com.example.newsfeed.domain.user.common.PasswordEncoder;
import com.example.newsfeed.domain.user.common.UserMapper;
import com.example.newsfeed.domain.user.dto.*;
import com.example.newsfeed.domain.user.entity.Friendship;
import com.example.newsfeed.domain.user.entity.User;
import com.example.newsfeed.domain.user.repository.FriendshipRepository;
import com.example.newsfeed.domain.user.repository.UserRepository;
import com.example.newsfeed.security.JwtUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final FriendshipRepository friendshipRepository;
    private final JwtUtil jwtUtil;


    //회원가입 signup
    @Transactional
    public Long signup(UserRequestDto dto) {
        userRepository.findByEmail(dto.getEmail()).ifPresent(u -> {
            throw new IllegalArgumentException("이메일이 이미 존재합니다.");
        });

        User user = UserMapper.toEntity(dto);

        //비밀번호 암호화
        user.setEncodedPassword(passwordEncoder.encode(dto.getPassword()));

        userRepository.save(user);

        return user.getId();
    }
    
    // 로그인
    public String login(LoginRequestDto dto){
        String userEmail = dto.getUserEmail();
        String password = dto.getPassword();

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("등록된 이메일이 없습니다"));

        if(!passwordEncoder.matches(password,user.getPassword())){
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다");
        }

        return jwtUtil.generateToken(user.getName());
    }



    // 회원탈퇴
    @Transactional
    public void withdrawal(Long id, String password) {
        User user = findByIdOrElseThrow(id);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new PasswordMismatchException("비밀번호가 올바르지 않습니다.");
        }
        userRepository.delete(user);
    }


    public UserResponseDto getProfile(Long id) {
        User user = findByIdOrElseThrow(id);

        return UserMapper.toResponseDto(user);
    }


    @Transactional
    public UserResponseDto updateProfile(Long id, UserRequestDto dto) {
        User user = findByIdOrElseThrow(id);

        user.updateProfile(dto.getUserName(), dto.getPhoneNumber(), dto.getBirth());
        return UserMapper.toResponseDto(user);
    }


    @Transactional
    public void updatePassword(Long id, String oldPassword, String newPassword) {

        User user = findByIdOrElseThrow(id);
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new PasswordMismatchException("비밀번호가 올바르지 않습니다.");
        }
        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new IllegalArgumentException("현재 비밀번호와 동일한 비밀번호로는 변경할 수 없습니다.");
        }

        user.setEncodedPassword(passwordEncoder.encode(newPassword));
    }


    @Transactional
    public void addFriend(Long id, Long friendId) {
        User user = findByIdOrElseThrow(id);
        User friend = findByIdOrElseThrow(friendId);
        //TODO 예외 던지기, if구문으로 검증 후 패스 어떤거 선택??
        if (!friendshipRepository.existsByUserAndFriend(user, friend)) {
            friendshipRepository.save(new Friendship(user, friend));
        }
    }


    @Transactional
    public void deleteFriend(Long id, Long friendId) {
        User user = findByIdOrElseThrow(id);
        User friend = findByIdOrElseThrow(friendId);
        // TODO 예외 던지기, 검증 후 패스 어떤거 선택??
//       Friendship friendship = friendshipRepository.findByUserAndFriend(user, friend).orElseThrow(() -> new EntityNotFoundException("유저(id:" + user.getId() + ")와 유저(id:" + friend.getId() + ")의 친구 관계가 아닙니다."));
        friendshipRepository.findByUserAndFriend(user, friend).ifPresent(friendshipRepository::delete);
    }


    public UserFollowResponseDto getUserFollow(Long id) {
        // TODO 개선 여부
        User user = findByIdOrElseThrow(id);
        return UserMapper.toFollowResponseDto(user);
    }


    private User findByIdOrElseThrow(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new EntityNotFoundException("유저(id:" + id + ")가 존재하지 않습니다."));
    }


}
