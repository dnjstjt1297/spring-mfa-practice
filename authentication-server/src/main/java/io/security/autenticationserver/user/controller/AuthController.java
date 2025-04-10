package io.security.autenticationserver.user.controller;

import io.security.autenticationserver.user.entity.Otp;
import io.security.autenticationserver.user.entity.User;
import io.security.autenticationserver.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/user/add")
    public void addUser(@RequestBody User user) {
        userService.addUser(user);
    }

    @PostMapping("/user/auth")
    public void auth(@RequestBody User user) {
        userService.auth(user);
    }

    @PostMapping("/user/otpCheck")
    public void otpCheck(@RequestBody Otp otp) {

    }
}





