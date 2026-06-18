package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Service
@RequiredArgsConstructor
public class FileStorageService {
    private final UserRepository userRepository;
    private final Path root = Paths.get("uploads").toAbsolutePath().normalize();

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(root);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize folder for uploads!", e);
        }
    }

    /**
     * Saves photo to disk, updates user in DB, and returns the URL.
     */
    public String saveProfilePhoto(MultipartFile file, User user) {
        try {
            if (file.isEmpty()) {
                throw new RuntimeException("Failed to store empty file.");
            }

            // 1. Generate a clean, unique filename
            String originalFilename = StringUtils.cleanPath(file.getOriginalFilename());
            String extension = StringUtils.getFilenameExtension(originalFilename);

            // Use User ID and Timestamp to ensure uniqueness and bypass browser cache
            String filename = "user_" + user.getId() + "_" + System.currentTimeMillis() + "." + extension;

            // 2. Resolve target location and copy file to 'uploads' folder
            Path targetLocation = this.root.resolve(filename);
            Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);

            // 3. Update the user entity with the new URL
            String photoUrl = "/uploads/" + filename;
            user.setPhotoUrl(photoUrl);
            userRepository.save(user);

            return photoUrl;

        } catch (IOException e) {
            throw new RuntimeException("Could not store file. Error: " + e.getMessage());
        }
    }
}
