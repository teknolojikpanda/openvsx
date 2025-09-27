/********************************************************************************
 * Copyright (c) 2024 Eclipse Foundation and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.security;

import org.eclipse.openvsx.UserService;
import org.eclipse.openvsx.entities.UserData;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;

import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNullElse;
import static org.eclipse.openvsx.entities.UserData.ROLE_ADMIN;
import static org.eclipse.openvsx.entities.UserData.ROLE_PRIVILEGED;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@Service
public class LdapUserService implements UserDetailsService {

    private final UserService userService;

    @Value("${ovsx.ldap.userSearchFilter:(uid={0})}")
    private String userSearchFilter;

    public LdapUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Create or update user data for LDAP user
        var userData = new UserData();
        userData.setLoginName(username);
        userData.setProvider("ldap");
        userData.setAuthId("ldap:" + username);
        userData.setFullName(username); // Can be enhanced to get from LDAP attributes
        userData.setEmail(username + "@company.com"); // Can be enhanced to get from LDAP attributes

        userData = userService.upsertUser(userData);
        
        return new LdapUserDetails(userData, getAuthorities(userData));
    }

    private Collection<GrantedAuthority> getAuthorities(UserData userData) {
        return switch (requireNonNullElse(userData.getRole(), "")) {
            case ROLE_ADMIN -> createAuthorityList("ROLE_ADMIN");
            case ROLE_PRIVILEGED -> createAuthorityList("ROLE_PRIVILEGED");
            default -> emptyList();
        };
    }

    public static class LdapUserDetails implements UserDetails {
        private final UserData userData;
        private final Collection<GrantedAuthority> authorities;

        public LdapUserDetails(UserData userData, Collection<GrantedAuthority> authorities) {
            this.userData = userData;
            this.authorities = authorities;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getPassword() {
            return "";
        }

        @Override
        public String getUsername() {
            return userData.getLoginName();
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

        public UserData getUserData() {
            return userData;
        }
    }
}