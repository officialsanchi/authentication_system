package com.authentication.AuthenticationSystem.controller;

import com.authentication.AuthenticationSystem.dtos.request.ChangePasswordRequest;
import com.authentication.AuthenticationSystem.dtos.request.PasswordResetRequest;
import com.authentication.AuthenticationSystem.dtos.response.MessageResponse;
import com.authentication.AuthenticationSystem.security.UserDetailsImpl;
import com.authentication.AuthenticationSystem.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/password")
@RequiredArgsConstructor
public class PasswordController {
    private final PasswordResetService passwordResetService;

    @PostMapping("/forgot")
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(passwordResetService.requestPasswordReset(request, httpRequest));
    }

    @PostMapping("/reset")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(passwordResetService.resetPassword(request, httpRequest));
    }

    @PostMapping("/change")
    public ResponseEntity<MessageResponse> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return ResponseEntity.ok(passwordResetService.changePassword(
                userDetails.getId(),
                request.getCurrentPassword(),
                request.getNewPassword(),
                httpRequest
        ));
    }
}
