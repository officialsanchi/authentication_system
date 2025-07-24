package com.authentication.AuthenticationSystem.service.interfaces;

import com.authentication.AuthenticationSystem.dtos.request.LoginUserRequest;
import com.authentication.AuthenticationSystem.dtos.request.LogoutUserRequest;
import com.authentication.AuthenticationSystem.dtos.request.RegisterUserRequest;
import com.authentication.AuthenticationSystem.dtos.response.LoginUserResponse;
import com.authentication.AuthenticationSystem.dtos.response.LogoutUserResponse;
import com.authentication.AuthenticationSystem.dtos.response.RegisterUserResponse;

public interface PrimaryUserService {
   RegisterUserResponse registerNewUser(RegisterUserRequest request);
   LoginUserResponse loginUser(LoginUserRequest request);
   LogoutUserResponse logoutUser(LogoutUserRequest request);

}
