package com.example.backend.test;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OAuth2User principal) {
        String name = principal != null ? principal.getAttribute("name") : "게스트";
        return "안녕하세요, " + name + "님!";
    }
}
