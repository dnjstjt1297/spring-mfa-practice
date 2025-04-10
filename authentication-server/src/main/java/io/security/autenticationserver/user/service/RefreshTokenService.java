package io.security.autenticationserver.user.service;

import io.security.autenticationserver.user.entity.RefreshToken;
import io.security.autenticationserver.user.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public String createRefreshToken(String username) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiry = LocalDateTime.now().plusDays(7);

        RefreshToken refreshToken = new RefreshToken(username, token, expiry);
        refreshTokenRepository.save(refreshToken);
        return token;
    }

    public boolean validateRefreshToken(String token){
        Optional<RefreshToken> o = refreshTokenRepository.findByToken(token);
        return o.isPresent() && o.get().getExpiryDate().isAfter(LocalDateTime.now());
    }

    public String getUsernameFromRefreshToken(String token){
        return refreshTokenRepository.findByToken(token)
                .map(RefreshToken::getUsername)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    public void removeRefreshToken(String token){
        refreshTokenRepository.deleteByToken(token);
    }

}
