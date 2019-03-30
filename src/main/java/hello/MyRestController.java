package hello;

import hello.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class MyRestController {
    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Autowired
    AuthValidator validator;

    @GetMapping("/info")
    public ResponseEntity<String> getInfo() {
        return ResponseEntity.ok("This is rest service");
    }

    @GetMapping(value = "/auth")
    public ResponseEntity<String> auth(@RequestParam(name = "auth") String auth) {
        if(validator.validate(auth)) {
            return ResponseEntity.ok(jwtTokenProvider.createToken(validator.extractUser(auth), DBMock.getOperations(validator.extractUser(auth))));
        } else {
            return ResponseEntity.badRequest().body("Invalid login/password");
        }
    }

    @GetMapping("/users")
    public ResponseEntity<String> getUsers() {
        return ResponseEntity.ok("[{\"fsdfsdf\",\"cvbcvbvc\"}]");
    }
}

class DBMock {
    public static List<String> getOperations(String username) {
        return Arrays.asList("123", "234", "345");
    }
}
