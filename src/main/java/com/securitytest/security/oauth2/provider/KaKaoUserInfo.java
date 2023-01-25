package com.securitytest.security.oauth2.provider;

import java.util.Map;

public class KaKaoUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;
    private Map<String, String> properties;
    private Map<String, String> account;

    public KaKaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
        properties = (Map<String, String>) attributes.get("properties");
        account = (Map<String, String>) attributes.get("kakao_account");
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
        return account.get("email");
    }

    @Override
    public String getName() {
        return properties.get("nickname");
    }
}
