package com.authentication.AuthenticationSystem.config;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CloudinaryConfig {
    @Bean
    public Cloudinary cloudinary(
            org.springframework.core.env.Environment env) {

        return new Cloudinary(
                ObjectUtils.asMap(
                        "cloud_name", env.getProperty("cloudinary.cloud-name"),
                        "api_key", env.getProperty("cloudinary.api-key"),
                        "api_secret", env.getProperty("cloudinary.api-secret")
                )
        );
    }
}
