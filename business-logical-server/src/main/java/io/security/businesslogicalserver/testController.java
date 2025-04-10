package io.security.businesslogicalserver;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class testController {

    @PostMapping("/test")
    public String test(){
        return "good";
    }

}
