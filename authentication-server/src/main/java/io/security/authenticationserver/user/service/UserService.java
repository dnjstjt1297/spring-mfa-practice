package io.security.authenticationserver.user.service;

import io.security.authenticationserver.otp.GeneratedCodeUtil;
import io.security.authenticationserver.otp.entity.Otp;
import io.security.authenticationserver.otp.repository.OtpRepository;
import io.security.authenticationserver.user.entity.User;
import io.security.authenticationserver.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpRepository otpRepository;

    public void addUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }


    public void auth(User user){
        Optional<User> o = userRepository.findUserByUsername(user.getUsername());

        if(o.isPresent()){
            User u = o.get();
            if(passwordEncoder.matches(user.getPassword(), u.getPassword())){
                reNewOtp(u);
            }
        } else {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    private void reNewOtp(User u) {
        String code = GeneratedCodeUtil.generateCode();

        Optional<Otp> userOtp = otpRepository.findOtpByUsername(u.getUsername());

        if(userOtp.isPresent()){
            Otp otp = userOtp.get();
            otp.setCode(code);
        } else {
            Otp otp = new Otp();
            otp.setUsername(u.getUsername());
            otp.setCode(code);
            otpRepository.save(otp);
        }

    }

    public boolean check(Otp otpToValidate){
        Optional<Otp> userOpt = otpRepository.findOtpByUsername(otpToValidate.getUsername());

        if(userOpt.isPresent()){
            Otp otp = userOpt.get();

            if(otpToValidate.getCode().equals(otp.getCode())){
                return true;
            }
        }

        return false;
    }
}
