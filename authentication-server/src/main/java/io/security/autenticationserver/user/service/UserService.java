package io.security.autenticationserver.user.service;

import io.security.autenticationserver.user.entity.Otp;
import io.security.autenticationserver.user.entity.User;
import io.security.autenticationserver.user.repository.OtpRepository;
import io.security.autenticationserver.user.repository.UserRepository;
import io.security.autenticationserver.util.CodeUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;

    public void addUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    public void auth(User user){
        Optional<User> o = userRepository.findUserByUsername(user.getUsername());
        if(o.isPresent()){
            User u = o.get();
            reNewOtp(u); // OTP 새로 발급
        } else {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    private void reNewOtp(User u) {
        String code = CodeUtil.generateCode(); // 랜덤 OTP 생성

        Optional<Otp> userOtp = otpRepository.findOtpByUsername(u.getUsername()); // 기존 OTP 조회

        if(userOtp.isPresent()){
            Otp otp = userOtp.get();
            otp.setCode(code); // 기존 OTP 코드 갱신
        } else {
            Otp otp = new Otp();
            otp.setUsername(u.getUsername());
            otp.setCode(code); // 새 OTP 코드 생성
            otpRepository.save(otp);
        }

    }

    public boolean isValidUser(String username, String rawPassword) {
        return userRepository.findUserByUsername(username)
                .filter(user -> passwordEncoder.matches(rawPassword, user.getPassword()))
                .isPresent();
    }

    public boolean isValidOtp(String username, String code) {
        return otpRepository.findOtpByUsername(username)
                .filter(otp -> otp.getCode().equals(code))
                .isPresent();
    }

}
