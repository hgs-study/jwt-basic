package com.hgstudy.jwtbasic.jwt;

import com.hgstudy.jwtbasic.cookie.CookieUtil;
import com.hgstudy.jwtbasic.redis.RedisUtil;
import com.hgstudy.jwtbasic.user.application.UserService;
import com.hgstudy.jwtbasic.user.entity.User;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends OncePerRequestFilter {


    private final JwtTokenProvider jwtTokenProvider;
    private final CookieUtil cookieUtil;
    private final UserService userService;
    private final RedisUtil redisUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        log.debug("===== [OncePerRequestFilter] doFilterInternal start =====");
        final Cookie jwtToken = cookieUtil.getCookie(request, JwtProperties.ACCESS_TOKEN_NAME);
        final Cookie refreshJwtToken = cookieUtil.getCookie(request, JwtProperties.REFRESH_TOKEN_NAME);
        String accessToken = jwtTokenProvider.resolveToken(request);

        String userKey = null;
        String jwt = null;
        String refreshJwt = null;
        String refreshUserKey = null;

        try{
//            log.debug("00000");
//            log.debug("jwtToken :"+ jwtToken);
//            log.debug("jwtToken.getValue() :"+ jwtToken.getValue());
//            log.debug("refreshJwtToken :"+ refreshJwtToken);
//            log.debug("refreshJwtToken.getValue() :"+ refreshJwtToken.getValue());
            log.debug("0.3 0.3 0.3 0.3");
//            jwtTokenProvider.validateToken(accessToken);
//            if(accessToken == null){
//                log.debug("0.4 0.4 0.4 0.4");
//                if(refreshJwtToken != null){
//                    log.debug("0.5 0.5 0.5 0.5");
//                    refreshJwt = refreshJwtToken.getValue();
//                    log.debug("refreshJwtToken.getValue() : "+refreshJwtToken.getValue());
//                }
//            }


//            if(jwtToken != null){
//                log.debug("1111111");
//                jwt = jwtToken.getValue();
//                userKey = jwtTokenProvider.getUserKeyByToken(jwt);
//            }


            if(accessToken != null){
                userKey = jwtTokenProvider.getUserKeyByToken(accessToken);
            }
//            else{
//                log.debug("1.1 1.1 1.1 1.1");
//                if(refreshJwtToken != null){
//                    log.debug("1.2 1.2 1.2 1.2 ");
//                    refreshUserKey = redisUtil.getData(refreshJwt);
//                    log.debug("refreshUserKey :"+refreshUserKey);
//                    log.debug("redisUtil.getData(refreshJwt) :"+redisUtil.getData(refreshJwt));
//                    log.debug("jwtTokenProvider.getUserKeyByToken(refreshJwt) :"+jwtTokenProvider.getUserKeyByToken(refreshJwt));
//
//                    if(refreshUserKey.equals(jwtTokenProvider.getUserKeyByToken(refreshJwt))){
//                        log.debug("8888");
//
//                        UserDetails userDetails = userService.findUserDetailsByUserKey(refreshUserKey);
//                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
//                        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//
//                        User user = userService.findByUserKey(refreshUserKey);
//                        String newToken =jwtTokenProvider.createToken(user.getUserKey(),
//                                user.getRoles(),
//                                JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME);
//                        Cookie newAccessToken = cookieUtil.createCookie(JwtProperties.ACCESS_TOKEN_NAME, newToken, JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME);
//                        log.debug("newToken : "+newToken);
//                        response.addCookie(newAccessToken);
//                    }
//                }
//            }

//            if(userKey != null){
//                log.debug("222222");
//                UserDetails userDetails = userService.findUserDetailsByUserKey(userKey);
//
//                if(isValidJwt(jwt)){
//                    log.debug("3333333");
//                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
//                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//                }


            if(userKey != null){
                log.debug("222222");
                UserDetails userDetails = userService.findUserDetailsByUserKey(userKey);

                if(isValidJwt(accessToken)){
                    log.debug("3333333");
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
        }catch (ExpiredJwtException e){ //Jwt 만료 시
            log.debug("4444444");
            Cookie refreshToken = cookieUtil.getCookie(request, JwtProperties.REFRESH_TOKEN_NAME);

            if(refreshToken!=null){
                log.debug("5555555");
                refreshJwt = refreshToken.getValue();
            }
        }catch(Exception e){
            log.debug("666666");
        }

        try{
            log.debug("6.5 6.5 6.5 6.5 6.5 6.5");
            if(refreshJwt != null){
                log.debug("777777");
                refreshUserKey = redisUtil.getData(refreshJwt);
                log.debug("refreshUserKey :"+refreshUserKey);
                log.debug("redisUtil.getData(refreshJwt) :"+redisUtil.getData(refreshJwt));
                log.debug("jwtTokenProvider.getUserKeyByToken(refreshJwt) :"+jwtTokenProvider.getUserKeyByToken(refreshJwt));

                if(refreshUserKey.equals(jwtTokenProvider.getUserKeyByToken(refreshJwt))){
                    log.debug("8888");

                    UserDetails userDetails = userService.findUserDetailsByUserKey(refreshUserKey);
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                    User user = userService.findByUserKey(refreshUserKey);
                    String newToken =jwtTokenProvider.createToken(user.getUserKey(),
                                                                  user.getRoles(),
                                                                  JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME);
                    Cookie newAccessToken = cookieUtil.createCookie(JwtProperties.ACCESS_TOKEN_NAME, newToken, JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME);
                    log.debug("newToken : "+newToken);
                    response.addCookie(newAccessToken);
                }
            }
        }catch(ExpiredJwtException e){
            log.debug("99999");

        }
        log.debug("10 10 10 10 10 10");
        chain.doFilter(request,response);

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
        log.debug("====== isValidJwt start======");
        return token != null && jwtTokenProvider.validateToken(token);
    }


}
