package com.hgstudy.jwtbasic.cookie;

import com.hgstudy.jwtbasic.jwt.JwtProperties;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
public class CookieUtil {
    public Cookie createCookie(String cookieName, String value){
        System.out.println("(int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME)111 = " + (int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME));
        System.out.println("(int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME) 222= " + (int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME/ 1000L));
        System.out.println("(int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME) 333= " + (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME/ 1000L));
        System.out.println("new Date().getTime() / 1000 " + new Date().getTime() / 1000);
        System.out.println("new Date().getTime() " + new Date().getTime() );
        Cookie token = new Cookie(cookieName,value);
        token.setHttpOnly(true);
        token.setMaxAge( (int) (JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME / 1000L));
        token.setPath("/");

        System.out.println("token.getMaxAge() = " + token.getMaxAge());
        return token;
    }

    public Cookie getCookie(HttpServletRequest req, String cookieName){
        final Cookie[] cookies = req.getCookies();

        if(isEmpty(cookies))
            return null;

        for(Cookie cookie : cookies){
            if(cookie.getName().equals(cookieName))
                return cookie;
        }

        return null;
    }

    private boolean isEmpty(Cookie[] cookies) {
        return cookies == null;
    }
}
