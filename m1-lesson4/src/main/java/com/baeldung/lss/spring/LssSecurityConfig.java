package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class LssSecurityConfig {

    private PasswordEncoder passwordEncoder;

    public LssSecurityConfig(PasswordEncoder passwordEncoder) {
        super();
        this.passwordEncoder = passwordEncoder;
    }

    //

     // @formatter:on
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.
                inMemoryAuthentication().
                passwordEncoder(passwordEncoder).
                withUser("admin").
                password(passwordEncoder.encode("admin")).
                roles("USER");
    }


    //Configuring custom login page using Lambdas
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {// @formatter:off
        http
        .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/delete/**").hasRole("ADMIN")
                .anyRequest().authenticated())
                .formLogin((formLogin) -> formLogin.loginPage("/login").permitAll().loginProcessingUrl("/doLogin"));
    return http.build();
    } // @formatter:on

}
