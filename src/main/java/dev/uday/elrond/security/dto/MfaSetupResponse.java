package dev.uday.elrond.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MfaSetupResponse {
    private String secret;
    private String qrCodeUrl;
}
