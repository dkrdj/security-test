package com.securitytest.security.handler;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
        RedirectAttributes redirectAttributes = (RedirectAttributes) request.getAttribute("redirectAttributes");
        redirectAttributes.addFlashAttribute("authorization", "Bearer " + authentication.getCredentials());
//        request.getRequestDispatcher("http://localhost:3000/oauth/redirect").forward(request, response);
        getRedirectStrategy().sendRedirect(request, response, "http://localhost:3000/oauth/redirect" + "?accessToken=accessToken1&refreshToken=refreshToken1");
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("왓나?");
        return UriComponentsBuilder.fromUriString("http://localhost:3000/oauth/redirect")
                .build().toUriString();
    }
}