package com.tripPlanner.project.commons;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class HomeController {

    // home 경로 맵핑
    @GetMapping("/")
    public String home() {
        log.info("Home !");
        return "redirect:/index.html";
    }
    
}
