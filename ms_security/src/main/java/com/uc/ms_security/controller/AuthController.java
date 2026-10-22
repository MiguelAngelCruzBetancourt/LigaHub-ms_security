package com.uc.ms_security.controller;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.CurrentUserResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public AuthResponseDTO login(
            @Valid @RequestBody LoginRequestDTO dto) {

        return authService.login(dto);
    }

    /** Usuario del token con roles y permisos; solo exige estar autenticado. */
    @GetMapping("/me")
    public CurrentUserResponseDTO me(Authentication authentication) {
        return authService.currentUser(Long.valueOf(authentication.getName()));
    }
}