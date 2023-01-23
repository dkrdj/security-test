package com.securitytest.security.oauth2.provider;

import java.util.Map;

public class KaKaoUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public KaKaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {
        return attributes.get("email").toString();
    }

    @Override
    public String getName() {
        return attributes.get("nickname").toString();
    }
}
