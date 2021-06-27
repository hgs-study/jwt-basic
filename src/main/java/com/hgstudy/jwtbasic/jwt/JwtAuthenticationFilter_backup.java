//package com.hgstudy.jwtbasic.jwt;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.filter.GenericFilterBean;
//
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.ServletRequest;
//import javax.servlet.ServletResponse;
//import javax.servlet.http.HttpServletRequest;
//import java.io.IOException;
//
//@RequiredArgsConstructor
//public class JwtAuthenticationFilter_backup extends GenericFilterBean {
//
//
//    private final JwtTokenProvider jwtTokenProvider;
//
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
//
//    private boolean isValidJwt(String token) {
//        return token != null && jwtTokenProvider.validateToken(token);
//    }
//
//
//}
