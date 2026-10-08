package com.authentication.AuthenticationSystem.dtos.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfilePhotoUrlRequest {

    @NotBlank(message = "Photo URL is required")
    private String photoUrl;
}
