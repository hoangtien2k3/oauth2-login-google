package com.hoangtien2k3.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(registry -> {
                    registry.requestMatchers("/", "/login").permitAll();
                    registry.anyRequest().authenticated();
                })
                .oauth2Login(oauth2LoginConfigurer -> {
                    oauth2LoginConfigurer
                            .defaultSuccessUrl("/profile")
                            .failureUrl("/login?error=true")
                            .authorizationEndpoint(authorizationEndpoint ->
                                    authorizationEndpoint.baseUri("/oauth2/authorization")
                            )
                            .redirectionEndpoint(redirectionEndpoint ->
                                    redirectionEndpoint.baseUri("/login/oauth2/code/*")
                            );
                })
                .build();
    }
}
