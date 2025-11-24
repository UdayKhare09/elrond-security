package dev.uday.elrond.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private String token;
    private String type = "Bearer";
    private boolean mfaRequired;
    private String mfaToken; // Temporary token if MFA is required

    public LoginResponse(String token) {
        this.token = token;
        this.mfaRequired = false;
    }

    public LoginResponse(String mfaToken, boolean mfaRequired) {
        this.mfaToken = mfaToken;
        this.mfaRequired = mfaRequired;
    }
}
