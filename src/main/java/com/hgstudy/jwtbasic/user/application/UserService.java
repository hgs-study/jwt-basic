package com.hgstudy.jwtbasic.user.application;


import com.hgstudy.jwtbasic.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    
    public UserDetails findUserDetailsByUserKey(String userKey) throws UsernameNotFoundException{
        System.out.println("userKey = " + userKey);
        return userRepository.findByUserKey(userKey)
                             .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                             .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }

    public User findByUserKey(String userKey) throws UsernameNotFoundException{
        return userRepository.findByUserKey(userKey)
                             .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }

    public User findByEmail(String email){
        return userRepository.findByEmail(email)
                             .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }


}
