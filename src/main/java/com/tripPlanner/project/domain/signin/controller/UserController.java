package com.tripPlanner.project.domain.signin.controller;


import com.tripPlanner.project.domain.destination.LikeService;
import com.tripPlanner.project.domain.login.auth.jwt.JwtTokenProvider;
import com.tripPlanner.project.domain.makePlanner.dto.PlannerDto;
import com.tripPlanner.project.domain.signin.repository.UserRepository;
import com.tripPlanner.project.domain.signin.service.UserService;
import com.tripPlanner.project.domain.signin.dto.UserDto;
import com.tripPlanner.project.domain.signin.entity.UserEntity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/check-id")
    public ResponseEntity<Map<String, Object>> checkUserId(@RequestBody Map<String, String> data) {
        String userid = data.get("userid");
        Optional<UserEntity> result = userRepository.findByUserid(userid);
        Map<String, Object> response = new HashMap<>();
        response.put("available", !result.isPresent());
        response.put("message", result.isPresent() ? "이미 사용 중인 ID입니다." : "사용 가능한 ID입니다.");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/check-email")
    public ResponseEntity<Map<String, Object>> checkEmail(@RequestBody Map<String, String> data) {
        String email = data.get("email");
        Optional<UserEntity> result = userRepository.findByEmail(email);
        Map<String, Object> response = new HashMap<>();

        // Optional 객체를 isPresent로 확인
        if (result.isPresent()) {
            response.put("available", false);
            response.put("message", "이미 사용 중인 이메일입니다.");
        } else {
            response.put("available", true);
            response.put("message", "사용 가능한 이메일입니다.");
        }

        System.out.println("이메일 중복 검사 요청: {}" + email);
        System.out.println("이메일 검색 결과: {}" + result);


        return ResponseEntity.ok(response);
    }

    @PostMapping("/send-auth-code")
    public ResponseEntity<Map<String, String>> sendAuthCode(@RequestBody Map<String, String> data) {
        String email = data.get("email");
        return userService.sendAuthCode(email);
    }


    @PostMapping("/verify-auth-code")
    public ResponseEntity<Map<String, String>> verifyAuthCode(@RequestBody Map<String, String> data) {
        String email = data.get("email");
        String code = data.get("code");
        String result = userService.verifyAuthCode(email, code);

        Map<String, String> response = new HashMap<>();
        response.put("message", result);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/join")
    public ResponseEntity<String> joinPost(@ModelAttribute UserDto userDto,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) {

        System.out.println("UserID : " + userDto.getUserid());
        System.out.println("UserPassword : " + userDto.getPassword());
        System.out.println("Controller username :" + userDto.getUsername());
        try {
            if (profileImage != null && !profileImage.isEmpty()) {
                String imagePath = userService.uploadProfileImage(userDto.getUserid(), profileImage);
                userDto.setImg(imagePath);
            }

            String result = userService.joinUser(userDto);
            if (result != null) {
                return ResponseEntity.badRequest().body(result);
            }
            return ResponseEntity.ok("회원가입 성공");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("회원가입 처리 중 오류가 발생했습니다.");
        }
    }
}

