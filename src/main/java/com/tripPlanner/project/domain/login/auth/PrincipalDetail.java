package com.tripPlanner.project.domain.login.auth;

import com.tripPlanner.project.domain.login.dto.LoginRequest;
import com.tripPlanner.project.domain.signin.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class PrincipalDetail implements UserDetails, OAuth2User {

    private LoginRequest loginRequest;
//    private UserEntity userEntity;
    private Map<String, Object> attributes;

    public PrincipalDetail(LoginRequest loginRequest){
        this.loginRequest = loginRequest;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(() -> "ROLE_USER");
    }

    @Override
    public String getPassword() {
        return loginRequest.getPassword();
    }

    @Override
    public String getUsername() {
        return loginRequest.getUsername();
    }

    @Override
    public String getName() {
        return loginRequest.getUserid();
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


    public UserEntity getUserEntity() { return this.getUserEntity();
    }
}
