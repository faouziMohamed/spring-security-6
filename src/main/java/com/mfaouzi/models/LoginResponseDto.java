package com.mfaouzi.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
@AllArgsConstructor
public class LoginResponseDto {
  private ApplicationUser user;
  private String jwt;
}
