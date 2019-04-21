package hello;

import hello.jwt.JwtTokenFilterConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity(debug = true)
@ComponentScan("hello.jwt")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private JwtTokenFilterConfigurer jwtConfigurer;

    @Autowired
    public WebSecurityConfig(JwtTokenFilterConfigurer jwtConfigurer) {
        this.jwtConfigurer = jwtConfigurer;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
            .authorizeRequests()
                .antMatchers("/home", "/info", "/auth").permitAll()
                .antMatchers("/users").hasAuthority("123")
                .antMatchers("/users22").hasAuthority("234")
                .anyRequest().authenticated()
                .and()
                .apply(jwtConfigurer)
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
             User.withDefaultPasswordEncoder()
                .username("user").password("password").roles("123")
//                .username("user2").password("password2").roles("234")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
}