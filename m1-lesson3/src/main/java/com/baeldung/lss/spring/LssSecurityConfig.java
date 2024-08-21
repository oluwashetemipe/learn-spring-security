package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class LssSecurityConfig  {

    private PasswordEncoder passwordEncoder;

    public LssSecurityConfig(PasswordEncoder passwordEncoder) {
        super();
        this.passwordEncoder = passwordEncoder;
    }

    //

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.
                inMemoryAuthentication().
                passwordEncoder(passwordEncoder).
                withUser("admin").
                password(passwordEncoder.encode("admin")).
                roles("USER");
    }

    //configuring authorization, overrides base class configuration method
    //base method defines that all requests in application must be authenticated and provides login form
    //builds on top of the method configuration
    //Before spring 3 and Spring Security 6
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/delete/**").hasRole("ADMIN")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .and()
//                .httpBasic();
//
//    }

    //Spring boot 3 and Spring Security 6
    //Authorization manager based solution for URL authorization
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("delete/**").hasRole("ADMIN")//principal must have ROLE_ADMIN for cleaner version use hasAuthority, for checking multiple authorities and either would be okay use hasAnyAuthority and hasAnyRole
                        //other api's like hasIpAddress to pinpoint a specific address, access allows expressions, anonymous allows any type of access, authenticated to ensure authentication, denyAll restricts any type of access, fullyAuthenticated...
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

}
