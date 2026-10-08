package com.authentication.AuthenticationSystem.service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CloudinaryService {
    private final Cloudinary cloudinary;

    public String uploadProfilePhoto(MultipartFile file) {

        try {

            Map<?, ?> result =
                    cloudinary.uploader()
                            .upload(
                                    file.getBytes(),
                                    ObjectUtils.asMap(
                                            "folder",
                                            "authentication-system/users"
                                    )
                            );

            return result.get("secure_url").toString();

        } catch (Exception ex) {
            throw new RuntimeException(
                    "Failed to upload image",
                    ex
            );
        }
    }
}
