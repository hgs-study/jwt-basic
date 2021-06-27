package com.hgstudy.jwtbasic.user.api;

import com.hgstudy.jwtbasic.jwt.JwtTokenProvider;
import com.hgstudy.jwtbasic.user.application.UserRepository;
import com.hgstudy.jwtbasic.user.form.UserForm.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.hgstudy.jwtbasic.user.entity.User;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // 회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Request.SignUp signUp) {
        return userRepository.save(User.builder()
                                        .email(signUp.getEmail())
                                        .userId(UUID.randomUUID().toString())
                                        .password(passwordEncoder.encode(signUp.getPassword()))
                                        .roles(Collections.singletonList("ROLE_USER")) // 최초 가입시 USER 로 설정
                                        .build())
                             .getId();
    }

    // 로그인
//    @PostMapping("/login")
//    public String login(@RequestBody Request.Login login) {
//        User member = userRepository.findByEmail(login.getEmail())
//                                        .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
//
//        if (!isMatchPassword(login, member)) {
//            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
//        }
//
//        System.out.println(" login start= ");
//        return jwtTokenProvider.createToken(member.getUserId(), member.getRoles());
//    }

    private boolean isMatchPassword(Request.Login login, User member) {
        return passwordEncoder.matches(login.getPassword(), member.getPassword());
    }
}
