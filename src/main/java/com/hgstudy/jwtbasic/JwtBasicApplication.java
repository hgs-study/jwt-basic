package com.hgstudy.jwtbasic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.annotation.PostConstruct;
import java.util.Date;
import java.util.TimeZone;

@SpringBootApplication
public class JwtBasicApplication {

//    @PostConstruct
//    public void setAsiaTime(){
//        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
//        System.out.println("현재 시각 :" + new Date());
//    }

    public static void main(String[] args) {
        SpringApplication.run(JwtBasicApplication.class, args);
    }




}
