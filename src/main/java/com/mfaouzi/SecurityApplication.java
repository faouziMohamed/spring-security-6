package com.mfaouzi;

import com.mfaouzi.models.Role;
import com.mfaouzi.repository.RoleRepository;
import com.mfaouzi.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityApplication {

  public static void main(String[] args) {
    SpringApplication.run(SecurityApplication.class, args);
  }

  @Bean
  CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
    return args -> {
      if (roleRepository.findByAuthority("ADMIN").isEmpty()) {
        Role adminRole = new Role("ADMIN");
        roleRepository.save(adminRole);
      }

      if (roleRepository.findByAuthority("USER").isEmpty()) {
        Role userRole = new Role("USER");
        roleRepository.save(userRole);
      }
    };
  }
}
