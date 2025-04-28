package com.tripPlanner.project.domain.login;

import com.tripPlanner.project.domain.login.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;


@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private AuthService authService;

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String,Object>> handleIllegalArgumentException(IllegalArgumentException ex){
        Map<String,Object> response = new HashMap<>();
        log.error("IllegalArgumentException 발생: {}", ex.getMessage()); // 예외 메시지 로깅
        response.put("error","Bad Request");
        response.put("message",ex.getMessage());
        response.put("status",400);
        return ResponseEntity
                .status(400)
                .body(response);
    }

    @ExceptionHandler(Exception.class)      //자세한 예외로 수정해야함
    public ResponseEntity<Map<String,Object>> handleException(Exception ex){
        Map<String,Object> response = new HashMap<>();
        log.error("Exception 발생: {}", ex.getMessage()); // 예외 메시지 로깅
        response.put("error","Bad Request");
        response.put("message",ex.getMessage());
        response.put("status",400);
        return ResponseEntity
                .status(400)
                .body(response);
    }


}
