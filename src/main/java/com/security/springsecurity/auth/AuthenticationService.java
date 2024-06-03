package com.security.springsecurity.auth;

import com.security.springsecurity.config.JwtService;
import com.security.springsecurity.user.Role;
import com.security.springsecurity.user.User;
import com.security.springsecurity.user.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Value("${application.security.jwt.cookie.name}")
    private String REFRESH_TOKEN_COOKIE_NAME;
    @Value("${application.security.jwt.cookie.expiration}")
    private int REFRESH_TOKEN_COOKIE_EXPIRATION;

    public AuthenticationResponse register(RegisterRequest request, HttpServletResponse httpServletResponse) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        setRefreshTokenCookie(refreshToken, httpServletResponse);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletResponse httpServletResponse) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        setRefreshTokenCookie(refreshToken, httpServletResponse);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthenticationResponse refreshToken(
            HttpServletRequest httpServletRequest) {
        final String userEmail;
        AuthenticationResponse authResponse = new AuthenticationResponse();

        String refreshToken = null;
        if (httpServletRequest.getCookies() != null) {
            for (Cookie cookie : httpServletRequest.getCookies()) {
                if (cookie.getName().equals(REFRESH_TOKEN_COOKIE_NAME)) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null) {
            return null;
        }

        userEmail = jwtService.extractUsername(refreshToken);

        if(userEmail != null) {
            UserDetails userDetails = userRepository.findByEmail(userEmail).orElseThrow();

            if(jwtService.isTokenValid(refreshToken, userDetails)) {
                String newAccessToken = jwtService.generateToken(userDetails);
                authResponse = AuthenticationResponse.builder()
                        .accessToken(newAccessToken)
                        .build();
            }
        }
        return authResponse;
    }

    private void setRefreshTokenCookie(String refreshToken, HttpServletResponse httpServletResponse) {
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge(REFRESH_TOKEN_COOKIE_EXPIRATION);
        httpServletResponse.addCookie(refreshTokenCookie);
    }
}
