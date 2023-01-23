package com.securitytest.config;

import com.securitytest.UserRepository;
import com.securitytest.jwt.JwtAuthenticationFilter;
import com.securitytest.jwt.JwtAuthorizationFilter;
import com.securitytest.jwt.JwtExceptionFilter;
import com.securitytest.security.handler.OAuth2AuthenticationFailureHandler;
import com.securitytest.security.handler.OAuth2AuthenticationSuccessHandler;
import com.securitytest.security.oauth2.CustomOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CorsConfig corsConfig;
    private final UserRepository userRepository;

    private final CustomOAuth2UserService customOAuth2UserService;

    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;


    @Autowired
    public SecurityConfig(CorsConfig corsConfig, UserRepository userRepository, CustomOAuth2UserService customOAuth2UserService, OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler, OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler) {
        this.corsConfig = corsConfig;
        this.userRepository = userRepository;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        return http
                .addFilter(corsConfig.corsFilter())
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeRequests()
                //인가
//                .antMatchers("/api/v1/user/**")
//                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//                .antMatchers("/api/v1/manager/**")
//                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//                .antMatchers("/api/v1/admin/**")
//                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .oauth2Login()
                .authorizationEndpoint(authorize -> {
                    authorize.baseUri("/oauth2/authorization");
                })
                .redirectionEndpoint(redirection -> {
                    redirection.baseUri("/login/oauth2/code/*");
                })
                .userInfoEndpoint(userInfo -> {
                    userInfo.userService(customOAuth2UserService);
                })
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
                .and()
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                .addFilterBefore(new JwtAuthorizationFilter(userRepository), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtExceptionFilter(), JwtAuthorizationFilter.class)
                .logout()
                .and()
                .build();
    }


}
