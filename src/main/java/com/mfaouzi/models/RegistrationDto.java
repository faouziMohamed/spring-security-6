package com.mfaouzi.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationDto {
  private String username;
  private String password;

  public String toString() {
    return "RegistrationDto(username=" + this.getUsername() + ", password=" + this.getPassword() + ")";
  }

}
