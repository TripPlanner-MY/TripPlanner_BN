package com.tripPlanner.project.domain.login.controller;


import com.tripPlanner.project.domain.login.auth.handler.CustomLogoutHandler;
import com.tripPlanner.project.domain.login.auth.jwt.JwtTokenProvider;
import com.tripPlanner.project.domain.login.dto.LoginRequest;
import com.tripPlanner.project.domain.login.dto.LoginResponse;
import com.tripPlanner.project.domain.login.service.AuthService;
import com.tripPlanner.project.domain.login.service.LoginService;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/user")
@CrossOrigin(origins = "http://localhost:3000") //리액트 도메인 허가
public class LoginController {

    private final LoginService loginService;
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomLogoutHandler customLogoutHandler;

    @GetMapping("/login")
    public String login(){
    log.info("LOGIN PAGE GET mapping");
    return "login";
    }

    @PostMapping(value="/login")
    @ResponseBody
    public ResponseEntity<LoginResponse> login_post(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse servletResponse
    ){
        log.info("login post mapping" + loginRequest);
      LoginResponse response = loginService.login(loginRequest); //loginDto 로 유저정보를 조회함
        System.out.println(response);
        if(!response.isSuccess()){
            return ResponseEntity.badRequest().body(response);
        }
        authService.setTokenCookies(servletResponse, response.getAccessToken()); //쿠키 저장
        servletResponse.setHeader("userid",loginRequest.getUserid());

    return ResponseEntity.ok(response); //Json 데이터로 전달
    }

    @PostMapping("/logout")
    @ResponseBody
    public ResponseEntity<?> logout_post(
            HttpServletRequest request, HttpServletResponse response
    ){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        customLogoutHandler.logout(request,response,authentication);
        
        return ResponseEntity.ok("로그아웃 처리 완료");
    }
    
    //아이디 찾기

    @PostMapping(value="/findId")
    @ResponseBody
    public ResponseEntity<?> findUserid(@RequestBody Map<String,String> request){
        String email = request.get("email");
        List<UserEntity> users = authService.findUserIdByEmail(email);

        if(!users.isEmpty()){
        //유저 ID 추출
            List<String> userids = users.stream()
                    .map(UserEntity::getUserid)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(Collections.singletonMap("userid",userids));

        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("message","유저를 찾을 수 없습니다")); 
        }
    }

    //유저 아이디 확인 메서드
    @PostMapping("/check-userid")
    @ResponseBody
    public ResponseEntity<?> checkUserid(@RequestBody Map<String,String> request){
        String userid = request.get("userid");

        boolean isExistsUserid = authService.existsByUserid(userid);

        if(isExistsUserid){
            return ResponseEntity.ok(Collections.singletonMap("message","사용자 ID가 확인되었습니다"));
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("message","해당 사용자 ID 가 없습니다"));
        }
    }

    //인증 메일 보내기
    @PostMapping("/send-verify-code")
    @ResponseBody
    public ResponseEntity<?> sendAuthCode(@RequestBody Map<String,String> request){
        String userid = request.get("userid");
        String email = request.get("email");

        log.info("userid {} ,email {} ",userid,email);

        Optional<UserEntity> optionalUser = authService.findByUseridAndEmail(userid, email);

        if(optionalUser.isPresent()){
            String code = authService.generateAuthCode(email);
            //이메일 발송
            authService.sendAuthMail(email,"인증 코드 요청",
                    "인증 코드는 다음과 같습니다:\n"+ code);

            return ResponseEntity.ok(Collections.singletonMap("message"," 인증코드가 이메일로 발송되었습니다"));
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("message","일치하는 사용자 정보를 찾을 수 없습니다."));
        }
    }
    
    //인증 코드 확인
    @PostMapping("/verify-code")
    @ResponseBody
    public ResponseEntity<?> verifyCode(@RequestBody Map<String,String> request){
        String userid = request.get("userid");
        String email = request.get("email");
        String code = request.get("code");
        log.info("userid {},email{},code,{}",userid,email,code);
        boolean isValid = authService.verifyCode(email,code);
        if(isValid){
            authService.removeCode(email); //코드 삭제
            
            String token = jwtTokenProvider.generateResetToken(userid,email); //비밀번호 재설정을 위한 토큰 생성

            Map<String,String> response = new HashMap<>();
            response.put("message","인증 성공");
            response.put("resetToken",token);

            return ResponseEntity.ok(response);
        }else{
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message","인증 코드가 유효하지 않습니다."));
        }
    }
    
    //인증 토큰 받은 후 비밀번호 변경
    @PostMapping("/reset-password")
    @ResponseBody
    public ResponseEntity<?> resetPassword(@RequestHeader("Authorization") String token , @RequestBody Map<String,String> request){
        String newPassword = request.get("newPassword");

        String userid = jwtTokenProvider.getUserIdFromToken(token);

        authService.updatePassword(userid,newPassword);

        return ResponseEntity.ok(Collections.singletonMap("message","비밀번호가 성공적으로 변경되었습니다"));
    }


    //리액트에서 인증정보 가져오기
    @GetMapping("/auth-check")
    @ResponseBody
    public ResponseEntity<?> checkAuth(){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || !authentication.isAuthenticated()){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok().build();
    }



}

