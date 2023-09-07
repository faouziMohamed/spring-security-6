package com.mfaouzi.services;

import com.mfaouzi.models.ApplicationUser;
import com.mfaouzi.models.LoginResponseDto;
import com.mfaouzi.models.Role;
import com.mfaouzi.repository.RoleRepository;
import com.mfaouzi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationService {

  private final PasswordEncoder passwordEncoder;
  private final RoleRepository roleRepository;
  private final UserRepository userRepository;
  private final AuthenticationManager authenticationManager;
  private final TokenService tokenService;

  public ApplicationUser registerUser(String username, String password) {
    String encodedPassword = passwordEncoder.encode(password);
    Role userRole = roleRepository.findByAuthority("USER").get();
    Set<Role> authorities = new HashSet<>();
    authorities.add(userRole);

    return userRepository.save(new ApplicationUser(0, username, encodedPassword, authorities));
  }

  public LoginResponseDto loginUser(String username, String password) {
    System.out.println("In the login user service " + username + " " + password);
    try {
      Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(username, password)
      );
      String token = tokenService.generateJwt(authentication);
      return new LoginResponseDto(userRepository.findByUsername(username).get(), token);
    } catch (AuthenticationException e) {
      System.out.println("In the login user service exception" + e.getMessage());
      return new LoginResponseDto(null, "");
    }
  }
}
