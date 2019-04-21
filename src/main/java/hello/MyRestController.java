package hello;

import hello.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@RestController
public class MyRestController {
    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Autowired
    AuthValidator validator;

    @GetMapping("/info")
    public ResponseEntity<Collection<? extends GrantedAuthority>> getInfo() {
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication().getAuthorities());
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

    @GetMapping("/users22")
    public ResponseEntity<String> getUsers2() {
        return ResponseEntity.ok("[{\"12312312\",\"23423432\"}]");
    }
}

class DBMock {
    public static List<String> getOperations(String username) {
        return Arrays.asList("123");
    }
}
