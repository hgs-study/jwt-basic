package com.hgstudy.jwtbasic.security;

import com.hgstudy.jwtbasic.cookie.CookieUtil;
import com.hgstudy.jwtbasic.jwt.CustomAuthenticationFilter;
import com.hgstudy.jwtbasic.jwt.JwtAuthenticationFilter;
import com.hgstudy.jwtbasic.jwt.JwtTokenProvider;
import com.hgstudy.jwtbasic.redis.RedisUtil;
import com.hgstudy.jwtbasic.user.application.UserRepository;
import com.hgstudy.jwtbasic.user.application.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;
    private final RedisUtil redisUtil;
    private final CookieUtil cookieUtil;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // authenticationManager를 Bean 등록합니다.
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers().frameOptions().disable();

        http
            .httpBasic().disable() // rest api 만을 고려하여 기본 설정은 해제하겠습니다.
            .csrf().disable() // csrf 보안 토큰 disable처리.
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 토큰 기반 인증이므로 세션 역시 사용하지 않습니다.
            .and()
            .authorizeRequests() // 요청에 대한 사용권한 체크
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/user/**").hasRole("USER").anyRequest()
            .permitAll() // 그외 나머지 요청은 누구나 접근 가능
            .and()
            .addFilter(new JwtAuthenticationFilter(authenticationManager(),jwtTokenProvider, userService,redisUtil,cookieUtil))
            .addFilterBefore(new CustomAuthenticationFilter(jwtTokenProvider, cookieUtil, userService, redisUtil),
                    UsernamePasswordAuthenticationFilter.class);
        // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣는다
    }


}
