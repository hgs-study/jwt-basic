package com.hgstudy.jwtbasic.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends OncePerRequestFilter {


    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        log.debug("[OncePerRequestFilter] doFilterInternal start");
        // 헤더에서 JWT 를 받아옵니다.
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
        log.debug("token = " + token);

        if (isValidJwt(token)) { // 유효한 토큰인지 확인합니다.
            System.out.println("성공");
            Authentication authentication = jwtTokenProvider.getAuthentication(token); // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
            SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext 에 Authentication 객체를 저장합니다.

        }
        chain.doFilter(request, response);
    }


    //    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        // 헤더에서 JWT 를 받아옵니다.
//        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
//
//        if (isValidJwt(token)) { // 유효한 토큰인지 확인합니다.
//            Authentication authentication = jwtTokenProvider.getAuthentication(token); // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
//            SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext 에 Authentication 객체를 저장합니다.
//
//        }
//        chain.doFilter(request, response);
//    }

    private boolean isValidJwt(String token) {
        log.debug("token = " + token);
        return token != null && jwtTokenProvider.validateToken(token);
    }


}
