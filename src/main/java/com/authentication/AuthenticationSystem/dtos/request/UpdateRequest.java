package com.authentication.AuthenticationSystem.dtos.request;

import lombok.Data;

@Data
public class UpdateRequest {
    private String username;
    private String phoneNumber;
}
