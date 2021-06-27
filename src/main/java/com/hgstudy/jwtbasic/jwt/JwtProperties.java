package com.hgstudy.jwtbasic.jwt;

public class JwtProperties {
    public static final String SECRET = "hgstudy";
    public static final long EXPIRATION_TIME = 30 * 60 * 1000L; // 30분
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";
}
