package com.authentication.AuthenticationSystem.service.implementations;

import com.authentication.AuthenticationSystem.data.repository.PrimaryUserRepository;
import com.authentication.AuthenticationSystem.dtos.request.LoginUserRequest;
import com.authentication.AuthenticationSystem.dtos.request.LogoutUserRequest;
import com.authentication.AuthenticationSystem.dtos.request.RegisterUserRequest;
import com.authentication.AuthenticationSystem.dtos.response.LoginUserResponse;
import com.authentication.AuthenticationSystem.dtos.response.LogoutUserResponse;
import com.authentication.AuthenticationSystem.dtos.response.RegisterUserResponse;
import com.authentication.AuthenticationSystem.service.interfaces.PrimaryUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PrimaryUserServiceImpl implements PrimaryUserService {

@Autowired
    private PrimaryUserRepository primaryUserRepository;

    @Override
    public RegisterUserResponse registerNewUser(RegisterUserRequest request) {
        return null;
    }

    @Override
    public LoginUserResponse loginUser(LoginUserRequest request) {
        return null;
    }

    @Override
    public LogoutUserResponse logoutUser(LogoutUserRequest request) {
        return null;
    }
}
