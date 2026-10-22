package com.uc.ms_security.service;

import com.uc.ms_security.dto.*;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    private final RoleRepository roleRepository;

    private final UserRoleService userRoleService;

    /** Rol que reciben los usuarios que se registran por su cuenta (nombre tal como está en la BD). */
    private static final String INITIAL_ROLE_NAME = "USUARIO INICIAL";

    /**
     * Autorregistro: crea el usuario y le asigna el rol inicial en una sola
     * transacción. Si el rol no existe no se crea el usuario.
     */
    @Transactional
    public UserResponseDTO register(CreateUserDTO dto) {
        Role initialRole = roleRepository
                .findByNameIgnoreCase(INITIAL_ROLE_NAME)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Rol inicial no encontrado: " + INITIAL_ROLE_NAME
                ));

        UserResponseDTO created = create(dto);

        AssignRoleRequestDTO assignment = new AssignRoleRequestDTO();
        assignment.setUserId(created.getId());
        assignment.setRoleId(initialRole.getId());
        userRoleService.assign(assignment);

        return created;
    }

    public UserResponseDTO create(CreateUserDTO dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new ApplicationException(
                ErrorCase.ALREADY_EXISTS,
                    "Ya existe un usuario con este email"
            );
        }
        String encodedPassword = passwordEncoder.encode(dto.getPassword());
        User user = userMapper.toEntity(dto, encodedPassword);
        User savedUser = userRepository.save(user);
        return userMapper.toResponseDTO(savedUser);
    }

    public List<UserResponseDTO> findAll() {
        List<User> users =userRepository.findAll();
        return userMapper.toResponseDTOList(users);
    }
    private User findUser(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new ApplicationException(
                ErrorCase.NOT_FOUND,
                "Usuario no encontrado con id: " + id
            ));
    }

    public UserResponseDTO findById(Long id) {
        User user = findUser(id);
        return userMapper.toResponseDTO(user);
    }

    public UserDetailResponseDTO findByIdAndProfile(Long id) {
        User user =userRepository
                        .findWithProfileById(id)
                        .orElseThrow(
                            () -> new ApplicationException(
                                ErrorCase.NOT_FOUND,
                                "Usuario no encontrado con id: " + id
                                )
                        );

        return userMapper.toDetailResponseDTO(user);
    }

    public UserResponseDTO update(Long id, UpdateUserDTO dto) {
        User user = findUser(id);
        if (userRepository.existsByEmailAndIdNot(dto.getEmail(), id)) {
            throw new ApplicationException(
                ErrorCase.ALREADY_EXISTS,
                    "El email pertenece a otro usuario"
            );
        }
        userMapper.updateBasicData(dto, user);

        if (dto.getPassword() != null && !dto.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(dto.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        return userMapper.toResponseDTO(updatedUser);
    }
    public UserResponseDTO updateStatus(Long id, UpdateUserStatusDTO dto) {
        User user = findUser(id);
        user.setActive(dto.getActive());
        return userMapper.toResponseDTO(userRepository.save(user));
    }
    public void delete(Long id) {
        User user = findUser(id);
        userRepository.delete(user);
    }
    public UserSessionsResponseDTO findByIdAndSessions(Long id) {
        User user = userRepository
                .findWithSessionsById(id)
                .orElseThrow(
                    () -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + id
                        )
                );

        return userMapper.toSessionsResponseDTO(user);
    }

    public UserRolesResponseDTO findByIdAndRoles(Long id) {
        User user = userRepository
                .findWithRolesById(id)
                .orElseThrow(
                    () -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + id
                        )
                );

        return userMapper.toRolesResponseDTO(user);
    }
}