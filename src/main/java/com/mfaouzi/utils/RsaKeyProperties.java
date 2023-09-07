package com.mfaouzi.utils;

import lombok.Data;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@Component
public class RsaKeyProperties {
  private final RSAPublicKey publicKey;
  private final RSAPrivateKey privateKey;

  public RsaKeyProperties() {
    KeyPair keyPair = KeyGeneratorUtility.generateRsaKeyPair();
    this.publicKey = (RSAPublicKey) keyPair.getPublic();
    this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
  }
}
