package hello;

import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Base64;

@Component
public class AuthValidator {
    public boolean validate(String base64userpassword) {
        String[] userpass = new String(Base64.getDecoder().decode(base64userpassword)).split(":");
        Assert.notNull(userpass[0], "No user found");
        String user = userpass[0];
        Assert.notNull(userpass[1], "No password found");
        String password = userpass[1];

        boolean valid = false;

        if(user.equals("user") && password.equals("password")) {
            valid = true;
        }

        return valid;
    }

    public String extractUser(String base64userpassword) {
        String[] userpass = new String(Base64.getDecoder().decode(base64userpassword)).split(":");
        Assert.notNull(userpass[0], "No user found");
        return userpass[0];
    }
}
