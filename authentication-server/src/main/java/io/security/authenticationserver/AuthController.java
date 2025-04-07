package io.security.authenticationserver;

import io.security.authenticationserver.user.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import io.security.authenticationserver.user.entity.User;
import io.security.authenticationserver.otp.entity.Otp;


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

    @PostMapping("/otp/check")
    public void checkOtp(@RequestBody Otp otp, HttpServletResponse response) {
        if(userService.check(otp)){
            response.setStatus(HttpServletResponse.SC_OK); // status = 200
        }
        else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // status = 403
        }
    }

}
