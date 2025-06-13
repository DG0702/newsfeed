package com.example.newsfeed.domain.user.controller;

import com.example.newsfeed.domain.user.dto.*;
import com.example.newsfeed.domain.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;



@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    // 아이디와 친구아이디 관계
    private void checkUserEqualsFriend(Long userId, Long FriendId){
        if(userId.equals(FriendId)){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"잘못된 요청입니다");
        }
    }



    // 회원 탈퇴
    @PostMapping("/{userId}")
    public ResponseEntity<Void> withdrawal(@PathVariable Long userId,
                                           @RequestBody UserDeleteRequestDto requestDto){

        userService.withdrawal(userId, requestDto.getPassword());

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }



    // 프로필 조회
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponseDto> selectUser(@PathVariable Long userId) {

        return ResponseEntity.status(HttpStatus.OK).body(userService.getProfile(userId));
    }

    // 프로필 수정
    @PatchMapping("/{userId}")
    public ResponseEntity<UserResponseDto> updateUser(@PathVariable Long userId,
                                                      @Valid @RequestBody UserRequestDto userRequestDto){

        return ResponseEntity.status(HttpStatus.OK).body(userService.updateProfile(userId,userRequestDto));
    }

    // 비밀번호 수정
    @PatchMapping("/{userId}/password")
    public ResponseEntity<Void> updatePassword(@PathVariable Long userId,
                                               @Valid @RequestBody UserUpdatePasswordRequestDto requestDto){



        userService.updatePassword(userId, requestDto.getOldPassword(), requestDto.getNewPassword());
        return ResponseEntity.status(HttpStatus.OK).build();
    }
    
    // 친구 추가
    @PostMapping("/{userId}/friendship")
    public ResponseEntity<Void> addFriend(@PathVariable Long userId,
                                          @RequestParam Long friendId){
        // userId, friendId 관계
        checkUserEqualsFriend(userId, friendId);

        userService.addFriend(userId, friendId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
    
    // 친구 삭제
    @DeleteMapping("/{userId}/friendship")
    public ResponseEntity<Void> deleteFriend(@PathVariable Long userId,
                                             @RequestParam Long friendId){
        // userId, friendId 관계
        checkUserEqualsFriend(userId, friendId);


        userService.deleteFriend(userId, friendId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    // (팔로우, 팔로워) 수, 목록
    @GetMapping("/{userId}/follow")
    public ResponseEntity<UserFollowResponseDto> getUserFollow(@PathVariable Long userId) {


        UserFollowResponseDto dto = userService.getUserFollow(userId);
        return ResponseEntity.status(HttpStatus.OK).body(dto);
    }
}
