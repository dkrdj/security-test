package com.securitytest.security.handler;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securitytest.dto.SocialLoginDto;
import com.securitytest.entity.User;
import com.securitytest.jwt.JwtProperties;
import com.securitytest.security.auth.UserDetailsCustom;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to ");
            return;
        }
        clearAuthenticationAttributes(request);
        UserDetailsCustom principal = (UserDetailsCustom) authentication.getPrincipal();
        User user = principal.getUser();
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("userSeq", user.getUserSeq())
                .withClaim("role", user.getRole())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
        PrintWriter writer = response.getWriter();
        ObjectMapper mapper = new ObjectMapper();
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME * 14))
                .withClaim("userSeq", user.getUserSeq())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
        SocialLoginDto socialLoginDto = new SocialLoginDto(accessToken, refreshToken);
        String jsonStr = null;
        try {
            jsonStr = mapper.writeValueAsString(socialLoginDto);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        writer.print(jsonStr);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("왓나?");
        return UriComponentsBuilder.fromUriString("http://localhost:3000/oauth/redirect")
                .build().toUriString();
    }
}