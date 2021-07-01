package com.hgstudy.jwtbasic.cookie;

import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@Component
public class CookieUtil {
    public Cookie createCookie(String cookieName, String value){
        Cookie token = new Cookie(cookieName,value);
        token.setHttpOnly(true);
        token.setMaxAge((int)JwtUtil.TOKEN_VALIDATION_SECOND);
        token.setPath("/");
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
