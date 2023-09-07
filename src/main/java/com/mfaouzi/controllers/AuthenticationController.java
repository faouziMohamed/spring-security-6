package com.mfaouzi.controllers;

import com.mfaouzi.models.ApplicationUser;
import com.mfaouzi.models.LoginResponseDto;
import com.mfaouzi.models.RegistrationDto;
import com.mfaouzi.services.AuthenticationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin("*")
public class AuthenticationController {
  private final AuthenticationService authenticationService;

  public AuthenticationController(AuthenticationService authenticationService) {
    this.authenticationService = authenticationService;
  }

  @PostMapping("/register")
  public ApplicationUser registerUser(@RequestBody RegistrationDto body) {
    System.out.println("In the register user controller" + body.toString());
    return authenticationService.registerUser(body.getUsername(), body.getPassword());
  }

  @PostMapping("/login")
  public LoginResponseDto loginUser(@RequestBody RegistrationDto body) {
    System.out.println("In the login user controller" + body.toString());
    return authenticationService.loginUser(body.getUsername(), body.getPassword());
  }
}

