package com.hgstudy.jwtbasic.user.form;

import com.hgstudy.jwtbasic.user.entity.User;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

public class UserForm {
    public static class Request{

        @Getter
        @Setter
        public static class SignUp {
            private String email;
            private String password;

            public User toEntity(){
                return new User(email,password);
            }
        }


        @Getter
        @Setter
        public static class Login {

            private String email;
            private String password;

            public User toEntity(){
                return new User(email,password);
            }
        }
    }

    public static class Response{

        @Getter
        @Setter
        public static class Find{
            private String email;
            private String name;
            private String password;
            private String userId;
            private Date createdAt;

            private String encryptedPwd;

            @Builder
            private Find(String email, String name, String password, String userId, Date createdAt, String encryptedPwd){
                this.email = email;
                this.name = name;
                this.password  = password;
                this.userId = userId;
                this.createdAt = createdAt;
                this.encryptedPwd = encryptedPwd;
            }

        }
    }
}
