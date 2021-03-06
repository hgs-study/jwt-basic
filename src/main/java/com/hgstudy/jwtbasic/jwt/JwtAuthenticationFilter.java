package com.hgstudy.jwtbasic.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hgstudy.jwtbasic.cookie.CookieUtil;
import com.hgstudy.jwtbasic.redis.RedisUtil;
import com.hgstudy.jwtbasic.user.application.UserRepository;
import com.hgstudy.jwtbasic.user.application.UserService;
import com.hgstudy.jwtbasic.user.entity.User;
import com.hgstudy.jwtbasic.user.form.UserForm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
    private UserService userService;
    private RedisUtil redisUtil;
    private CookieUtil cookieUtil;

    private final String ACCESS_TOKEN_NAME = JwtProperties.ACCESS_TOKEN_NAME;
    private final String REFRESH_TOKEN_NAME = JwtProperties.REFRESH_TOKEN_NAME;
    private final long REFRESH_TOKEN_EXPIRATION_TIME = JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME;
    private final long ACCESS_TOKEN_EXPIRATION_TIME = JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   JwtTokenProvider jwtTokenProvider,
                                   UserService userService,
                                   RedisUtil redisUtil,
                                   CookieUtil cookieUtil) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
        this.redisUtil = redisUtil;
        this.cookieUtil = cookieUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            log.debug("==== attemptAuthentication start ====");
            //"/login"??? 1????????? ??? / getInputStream() : post ????????? ?????? ?????? ?????? ??? ??????
            UserForm.Request.Login creds = new ObjectMapper().readValue(request.getInputStream(), UserForm.Request.Login.class);


            //UsernamePasswordAuthenticationToken ?????? ?????? ??? AuthenticationManager??? ???????????? ??????
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
        User member = userService.findByEmail(email);

        final String accessToken = jwtTokenProvider.createToken(member.getUserKey(), member.getRoles(), ACCESS_TOKEN_EXPIRATION_TIME);
        System.out.println("JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME = " + REFRESH_TOKEN_EXPIRATION_TIME);
        final String refreshToken = jwtTokenProvider.createToken(member.getUserKey(), member.getRoles(), REFRESH_TOKEN_EXPIRATION_TIME);

        final Cookie accessTokenCookie = cookieUtil.createCookie(ACCESS_TOKEN_NAME, accessToken, ACCESS_TOKEN_EXPIRATION_TIME);
        final Cookie refreshTokenCookie = cookieUtil.createCookie(REFRESH_TOKEN_NAME, refreshToken, REFRESH_TOKEN_EXPIRATION_TIME);

        redisUtil.setDataExpire(refreshToken, member.getUserKey() , JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME);

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);

        response.addHeader(JwtProperties.RESPONSE_HEADER_NAME,accessToken);
        response.addHeader("userId", member.getUserKey());
    }

}
