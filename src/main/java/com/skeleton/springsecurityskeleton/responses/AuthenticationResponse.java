package com.skeleton.springsecurityskeleton.responses;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
private String jwtToken;
}
