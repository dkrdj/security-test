package com.securitytest.security.auth;

import com.securitytest.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Data
public class UserDetailsCustom implements UserDetails, OAuth2User {
    private final User user;
    private Map<String, Object> attributes;

    // 일반 로그인
    public UserDetailsCustom(User user) {
        this.user = user;
    }

    // 소셜 로그인
    public UserDetailsCustom(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(user::getRole);
        return authorities;
    }

    @Override
    public String getName() {
        return user.getUserSeq() + ""; // userSeq를 문자열로 변환
    }
}
