package io.security.autenticationserver.user.service;

import io.security.autenticationserver.user.dto.TokenResponse;
import io.security.autenticationserver.user.entity.RefreshToken;
import io.security.autenticationserver.user.repository.RefreshTokenRepository;
import io.security.autenticationserver.util.TokenUtil;
import io.security.autenticationserver.user.entity.Otp;
import io.security.autenticationserver.user.entity.User;
import io.security.autenticationserver.user.repository.OtpRepository;
import io.security.autenticationserver.user.repository.UserRepository;
import io.security.autenticationserver.util.CodeUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    // 유저 저장
    public void addUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    // 유저 인증
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

    public String generateJwtToken(String username) throws Exception {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        List<SimpleGrantedAuthority> roles = new ArrayList<>();
        roles.add(authority);
        return TokenUtil.generateJwtToken(username, roles);
    }

    public String generateRefreshToken(String username){
        while (true) {
            try {
                RefreshToken refreshToken = TokenUtil.generateUuidToken(username);
                refreshTokenRepository.save(refreshToken);
                return refreshToken.getToken();
            } catch (DataIntegrityViolationException e) {
                // 중복이면 다시 생성 , 중복 가능성 0수렴 이유는 2^122조합이기 때문
            }
        }
    }

    public String getUsernameFromRefreshToken(String token){
        return refreshTokenRepository.findByToken(token)
                .map(RefreshToken::getUsername)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    public void removeRefreshToken(String token){
        refreshTokenRepository.deleteByToken(token);
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

    public boolean isValidRefreshToken(String token) {
        return refreshTokenRepository.existsByToken(token);
    }

    public TokenResponse responseRefreshToken(String token) throws Exception {
        Optional<RefreshToken> o = refreshTokenRepository.findByToken(token);

        if (o.isEmpty()) {
            throw new RuntimeException("Invalid refresh token"); // 혹은 커스텀 예외
        }

        RefreshToken refreshToken = o.get();
        String username = refreshToken.getUsername();

        String newAccessToken = generateJwtToken(username);
        String newRefreshToken = token;

        if (!refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(refreshToken);
            newRefreshToken = generateRefreshToken(username);
        }

        return new TokenResponse(newAccessToken, newRefreshToken);
    }
}
