package com.hgstudy.jwtbasic.jwt;

public class JwtProperties {
    public static final String SECRET = "hgstudy";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String REQUEST_HEADER_NAME = "Authorization";
    public static final String RESPONSE_HEADER_NAME = "Token";
    public static final String ACCESS_TOKEN = "Access_token";
    public static final String REFRESH_TOKEN = "Authorization";
    public static final long ACCESS_TOKEN_EXPIRATION_TIME = 2 * 60 * 1000L; // 2분
    public static final long REFRESH_TOKEN_EXPIRATION_TIME = 1 * 60 * 60 * 1000L; // 하루d
}
