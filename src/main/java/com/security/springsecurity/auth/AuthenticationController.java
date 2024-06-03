package com.security.springsecurity.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request,
            HttpServletResponse httpServletResponse
    ) {
        return ResponseEntity.ok(service.register(request, httpServletResponse));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request,
            HttpServletResponse httpServletResponse
    ) {
        return ResponseEntity.ok(service.authenticate(request, httpServletResponse));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refresh(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse
    ) {
        return ResponseEntity.ok(service.refreshToken(httpServletRequest));
    }
}
