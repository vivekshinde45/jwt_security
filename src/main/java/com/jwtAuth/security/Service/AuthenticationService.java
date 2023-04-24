package com.jwtAuth.security.Service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwtAuth.security.Config.JwtService;
import com.jwtAuth.security.Entities.Role;
import com.jwtAuth.security.Entities.User;
import com.jwtAuth.security.Payload.AuthenticationRequest;
import com.jwtAuth.security.Payload.AuthenticationResponse;
import com.jwtAuth.security.Payload.RegisterRequest;
import com.jwtAuth.security.Repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository _userRepository;

    private final PasswordEncoder _passwordEncoder;

    private final JwtService _jwtService;

    private final AuthenticationManager _authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(_passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        _userRepository.save(user);
        var jwtToken = _jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        _authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()));
        var user = this._userRepository.findByEmail(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        var jwtToken = _jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

}
