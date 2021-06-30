package com.hgstudy.jwtbasic.jwt;

import com.hgstudy.jwtbasic.user.application.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtTokenProvider {

    private String secretKey = JwtProperties.SECRET;

    private final UserService userService;

    //객체 초기화, secretKey를 base64로 인코딩한다.
    @PostConstruct
    protected void init(){
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성
    public String createToken(String userPk, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(userPk); // JWT payload 에 저장되는 정보단위
        claims.put("roles", roles); // 정보는 key / value 쌍으로 저장된다.
        Date now = new Date();

        return Jwts.builder()
                    .setClaims(claims) // 정보 저장
                    .setIssuedAt(now) // 토큰 발행 시간 정보
                    .setExpiration(new Date(now.getTime() + JwtProperties.EXPIRATION_TIME)) // set Expire Time
                    .signWith(SignatureAlgorithm.HS256, secretKey)  // 사용할 암호화 알고리즘과 signature 에 들어갈 secret값 세팅
                    .compact();
    }


    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userService.findByUserId(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 토큰에서 회원 정보 추출
    public String getUserPk(String token) {
        log.debug("secretKey :"+ secretKey);
        return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
    }

    // Request의 Header에서 token 값을 가져옵니다. "Authorization" : "TOKEN값'
    public String resolveToken(HttpServletRequest request) {
        String token = request.getHeader(JwtProperties.REQUEST_HEADER_NAME);
        if (StringUtils.hasText(token) && token.startsWith(JwtProperties.TOKEN_PREFIX)) {
            token = token.replace(JwtProperties.TOKEN_PREFIX,"");
            log.debug("token : "+token);
        }
        return token;
//        return request.getHeader(JwtProperties.REQUEST_HEADER_NAME);
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            //log.debug("jwtToken before: "+jwtToken);
            //jwtToken = jwtToken.replace(JwtProperties.TOKEN_PREFIX,"");
            log.debug("jwtToken after: "+jwtToken);
            Jws<Claims> claims = Jwts.parser()
                                     .setSigningKey(secretKey)
                                     .parseClaimsJws(jwtToken);

            if(false == !claims.getBody().getExpiration().before(new Date()))
                System.out.println("만료된 토큰입니다.");
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }


}
