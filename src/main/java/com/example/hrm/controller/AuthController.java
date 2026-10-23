package com.example.hrm.controller;

import com.example.hrm.dto.req.LoginRequest;
import com.example.hrm.dto.req.RegisterRequest;
import com.example.hrm.entity.User;
import com.example.hrm.security.jwt.JwtProvider;
import com.example.hrm.security.UserPrincipal;
import com.example.hrm.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    @PostMapping("/register")
    public ResponseEntity<User> register(
            @RequestBody RegisterRequest request) {

        User user = userService.createUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            User user = ((UserPrincipal) Objects.requireNonNull(
                    authentication.getPrincipal()
            )).getUser();

            String role = authentication.getAuthorities()
                    .stream()
                    .findFirst()
                    .map(GrantedAuthority::getAuthority)
                    .orElse(user.getRole());

            String token = jwtProvider.generateToken(
                    user.getUsername(),
                    role
            );

            return ResponseEntity.ok(Map.of(
                    "accessToken", token,
                    "type", "Bearer",
                    "username", user.getUsername()
            ));

        } catch (AuthenticationException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message",
                            "username or password incorrect"
                    ));
        }
    }
}