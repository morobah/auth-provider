package org.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

@RestController
public class UserController {
    @Autowired
    private TokenStore tokenStore;

    @RequestMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }

    @RequestMapping("/oauth/revoke-token")
    @ResponseStatus(HttpStatus.OK)
    public void revokeToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            String tokenValue = authHeader.replace("Bearer", "").trim();
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
            if (accessToken != null) {
                if (accessToken.getRefreshToken() != null) {
                    tokenStore.removeRefreshToken(accessToken.getRefreshToken());
                }
                this.tokenStore.removeAccessToken(accessToken);
            }
        }
    }

    @RequestMapping("/logout")
    public void exit(HttpServletRequest request, HttpServletResponse response) {
        new SecurityContextLogoutHandler().logout(request, null, null);
        try {
            response.sendRedirect(request.getHeader("referer"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
