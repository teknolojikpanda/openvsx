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

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class LdapAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticationSuccessHandler.class);

    private final String redirectUrl;
    private final org.eclipse.openvsx.UserService userService;
    private final UserAttributesMapper attrsMapper;
    private final GroupRoleResolver roleResolver;
    private final String userSearchBase;
    private final String ldapBase;

    public LdapAuthenticationSuccessHandler(String redirectUrl, org.eclipse.openvsx.UserService userService, 
                                          org.springframework.ldap.core.LdapTemplate ldapTemplate,
                                          String userSearchBase, String groupSearchBase, String groupSearchFilter, String adminGroups, String ldapBase) {
        this.redirectUrl = redirectUrl;
        this.userService = userService;
        this.userSearchBase = userSearchBase;
        this.ldapBase = ldapBase;
        this.attrsMapper = new UserAttributesMapper(ldapTemplate, userSearchBase);
        this.roleResolver = new GroupRoleResolver(ldapTemplate, groupSearchBase, groupSearchFilter, adminGroups);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("LDAP Authentication Success! Redirecting to: " + redirectUrl);
        
        Object p = authentication.getPrincipal();
        if (p instanceof LdapUserService.LdapUserDetails custom) {
            handleCustom(custom, authentication);
        } else if (p instanceof org.springframework.security.ldap.userdetails.LdapUserDetailsImpl springLdap) {
            handleSpring(springLdap, authentication);
        } else {
            logger.info("Authenticated: {}", authentication.getName());
        }
        
        writeSuccess(response);
    }

    private void handleCustom(LdapUserService.LdapUserDetails ldapUser, Authentication oldAuth) {
        var userData = ldapUser.getUserData();
        var idPrincipal = new IdPrincipal(userData.getId(), userData.getLoginName(), new java.util.ArrayList<>(ldapUser.getAuthorities()));
        
        var newAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            idPrincipal, oldAuth.getCredentials(), oldAuth.getAuthorities());
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(newAuth);
        
        logger.info("User authenticated: " + userData.getLoginName());
    }

    private void handleSpring(org.springframework.security.ldap.userdetails.LdapUserDetailsImpl usr, Authentication oldAuth) {
        String username = usr.getUsername();
        logger.info("Creating user session for LDAP user: " + username);
        
        var ua = attrsMapper.map(username);
        String role = roleResolver.resolve(username, userSearchBase, ldapBase);
        
        var userData = new org.eclipse.openvsx.entities.UserData();
        userData.setLoginName(username);
        userData.setProvider("ldap");
        userData.setAuthId("ldap:" + username);
        userData.setFullName(ua.fullName());
        userData.setEmail(ua.email());
        userData.setRole(role);
        
        userData = userService.upsertUser(userData);
        
        var authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();
        if (org.eclipse.openvsx.entities.UserData.ROLE_ADMIN.equals(role)) {
            authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"));
        
        var idPrincipal = new IdPrincipal(userData.getId(), username, authorities);
        var newAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            idPrincipal, oldAuth.getCredentials(), authorities);
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(newAuth);
        
        logger.info("User session created for: " + username);
    }

    private void writeSuccess(HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        response.setStatus(200);
        response.getWriter().write("{\"success\":true}");
    }

}