package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.CurrentUserResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.entity.Profile;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final PermissionMapper permissionMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthResponseDTO login(LoginRequestDTO dto) {
        User user = userRepository.findByEmail(dto.getEmail())
                .orElseThrow(this::unauthorized);

        boolean validPassword = passwordEncoder.matches(
                dto.getPassword(),
                user.getPassword()
        );

        if (!validPassword) {
            throw unauthorized();
        }

        if (!user.isActive()) {
            throw new ApplicationException(
                    ErrorCase.UNAUTHORIZED,
                    "El usuario está desactivado"
            );
        }

        return jwtService.generateToken(user);
    }

    /**
     * Identidad del usuario del token con sus roles y permisos efectivos.
     * No pasa por la autorización dinámica: cualquier usuario activo puede
     * consultarse a sí mismo, aunque su rol no tenga ningún permiso.
     */
    @Transactional(readOnly = true)
    public CurrentUserResponseDTO currentUser(Long userId) {
        User user = userRepository.findWithRolesById(userId)
                .filter(User::isActive)
                .orElseThrow(this::unauthorized);

        Profile profile = user.getProfile();

        return new CurrentUserResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                profile != null ? profile.getPhotoUrl() : null,
                user.getUserRoles().stream()
                        .map(userRole -> userRole.getRole().getName())
                        .toList(),
                permissionMapper.toResponseDTOList(
                        permissionRepository.findAllByUserId(userId)
                )
        );
    }

    private ApplicationException unauthorized() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "Credenciales incorrectas"
        );
    }
}