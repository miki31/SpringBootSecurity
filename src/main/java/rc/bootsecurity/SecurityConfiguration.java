package rc.bootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("admin")
                    .password(passwordEncoder().encode("admin123"))
                    .roles("ADMIN")
                    .authorities("ACCESS_TEST1", "ACCESS_TEST2")
                .and()
                .withUser("misha")
                    .password(passwordEncoder().encode("misha123"))
                    .roles("USER")
                .and()
                .withUser("manager")
                    .password(passwordEncoder().encode("manager123"))
                    .roles("MANAGER")
                    .authorities("ACCESS_TEST1");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
//                .anyRequest().authenticated()     // access to all functions without permission
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()  // "/profile/index" --> can connect to that file;   "/profile/**" --> can connect to all files in folder "profile"
                .antMatchers("/admin/**").hasRole("ADMIN")   // .authenticated() --> permission for all authenticated users
                .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")  // .hasRole("ADMIN") --> permission for user who is authenticated and has a role "ADMIN"

                // add secure to REST API controller
//                .antMatchers("/api/public/**").hasRole("ADMIN") // "/api/public/**" --> for all inner url
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")

                .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
