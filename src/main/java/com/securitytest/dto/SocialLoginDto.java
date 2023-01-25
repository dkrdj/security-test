package com.securitytest.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SocialLoginDto {
    private String accessToken;
    private String refreshToken;
}
