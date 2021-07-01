package com.hgstudy.jwtbasic.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hgstudy.jwtbasic.cookie.CookieUtil;
import com.hgstudy.jwtbasic.redis.RedisUtil;
import com.hgstudy.jwtbasic.user.application.UserRepository;
import com.hgstudy.jwtbasic.user.entity.User;
import com.hgstudy.jwtbasic.user.form.UserForm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private JwtTokenProvider jwtTokenProvider;
    private UserRepository userRepository;
    private RedisUtil redisUtil;
    private CookieUtil cookieUtil;

    private final String ACCESS_TOKEN_NAME = JwtProperties.ACCESS_TOKEN_NAME;
    private final String REFRESH_TOKEN_NAME = JwtProperties.REFRESH_TOKEN_NAME;
    private final long REFRESH_TOKEN_EXPIRATION_TIME = JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME;
    private final long ACCESS_TOKEN_EXPIRATION_TIME = JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   JwtTokenProvider jwtTokenProvider,
                                   UserRepository userRepository,
                                   RedisUtil redisUtil,
                                   CookieUtil cookieUtil) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
        this.redisUtil = redisUtil;
        this.cookieUtil = cookieUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            log.debug("==== attemptAuthentication start ====");
            //"/login"시 1번째로 탐 / getInputStream() : post 형태로 오는 것을 받을 수 있음
            UserForm.Request.Login creds = new ObjectMapper().readValue(request.getInputStream(), UserForm.Request.Login.class);


            //UsernamePasswordAuthenticationToken 토큰 생성 후 AuthenticationManager에 인증작업 요청
            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getEmail(),
                            creds.getPassword(),
                            new ArrayList<>()
                    )
            );
        } catch (IOException e){
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        log.debug("==== successfulAuthentication start ====");
        String email = ((User)authResult.getPrincipal()).getEmail();
        User member = userRepository.findByEmail(email)
                                    .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));

        final String accessToken = jwtTokenProvider.createToken(member.getUserId(), member.getRoles(), ACCESS_TOKEN_EXPIRATION_TIME);
        System.out.println("JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME = " + REFRESH_TOKEN_EXPIRATION_TIME);
        final String refreshToken = jwtTokenProvider.createToken(member.getUserId(), member.getRoles(), REFRESH_TOKEN_EXPIRATION_TIME);

        final Cookie accessTokenCookie = cookieUtil.createCookie(ACCESS_TOKEN_NAME, accessToken);
        final Cookie refreshTokenCookie = cookieUtil.createCookie(REFRESH_TOKEN_NAME, refreshToken);

        redisUtil.setDataExpire(refreshToken, email, JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME);

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        response.addHeader(JwtProperties.RESPONSE_HEADER_NAME,accessToken);
        response.addHeader("userId", member.getUserId());
    }

}
