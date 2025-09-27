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
    private final org.springframework.ldap.core.LdapTemplate ldapTemplate;

    public LdapAuthenticationSuccessHandler(String redirectUrl, org.eclipse.openvsx.UserService userService, org.springframework.ldap.core.LdapTemplate ldapTemplate) {
        this.redirectUrl = redirectUrl;
        this.userService = userService;
        this.ldapTemplate = ldapTemplate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("LDAP Authentication Success! Redirecting to: " + redirectUrl);
        
        logger.info("Principal type: " + authentication.getPrincipal().getClass().getName());
        logger.info("Principal: " + authentication.getPrincipal());
        
        // Create IdPrincipal from LDAP user details
        if (authentication.getPrincipal() instanceof LdapUserService.LdapUserDetails ldapUser) {
            var userData = ldapUser.getUserData();
            var idPrincipal = new IdPrincipal(userData.getId(), userData.getLoginName(), new java.util.ArrayList<>(ldapUser.getAuthorities()));
            
            // Update the authentication with IdPrincipal
            var newAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                idPrincipal, authentication.getCredentials(), authentication.getAuthorities());
            org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(newAuth);
            
            logger.info("User authenticated: " + userData.getLoginName());
        } else if (authentication.getPrincipal() instanceof org.springframework.security.ldap.userdetails.LdapUserDetailsImpl ldapDetails) {
            // Handle Spring's LdapUserDetailsImpl
            String username = ldapDetails.getUsername();
            logger.info("Creating user session for LDAP user: " + username);
            
            // Query LDAP for user attributes
            String fullName = username; // fallback to username
            String email = username + "@company.com"; // fallback email
            try {
                // Search for user in LDAP to get attributes
                var searchControls = new javax.naming.directory.SearchControls();
                searchControls.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
                searchControls.setReturningAttributes(new String[]{"displayName", "givenName", "sn", "cn", "mail", "email"});
                
                var results = ldapTemplate.search(
                    "ou=users", 
                    "(uid=" + username + ")", 
                    searchControls,
                    (org.springframework.ldap.core.AttributesMapper<String[]>) attrs -> {
                        String displayName = attrs.get("displayName") != null ? (String) attrs.get("displayName").get() : null;
                        String fullNameResult = username;
                        if (displayName != null && !displayName.trim().isEmpty()) {
                            fullNameResult = displayName;
                        } else {
                            String givenName = attrs.get("givenName") != null ? (String) attrs.get("givenName").get() : null;
                            String surname = attrs.get("sn") != null ? (String) attrs.get("sn").get() : null;
                            if (givenName != null && surname != null) {
                                fullNameResult = givenName + " " + surname;
                            } else {
                                String cn = attrs.get("cn") != null ? (String) attrs.get("cn").get() : null;
                                if (cn != null && !cn.equals(username)) {
                                    fullNameResult = cn;
                                }
                            }
                        }
                        
                        String emailResult = attrs.get("mail") != null ? (String) attrs.get("mail").get() : null;
                        if (emailResult == null) {
                            emailResult = attrs.get("email") != null ? (String) attrs.get("email").get() : null;
                        }
                        
                        return new String[]{fullNameResult, emailResult};
                    });
                if (!results.isEmpty() && results.get(0) != null) {
                    String[] userInfo = results.get(0);
                    if (userInfo[0] != null) fullName = userInfo[0];
                    if (userInfo[1] != null) email = userInfo[1];
                }
            } catch (Exception e) {
                logger.warn("Could not query LDAP for user attributes: " + e.getMessage());
            }
            
            // Create user data for LDAP user
            var userData = new org.eclipse.openvsx.entities.UserData();
            userData.setLoginName(username);
            userData.setProvider("ldap");
            userData.setAuthId("ldap:" + username);
            userData.setFullName(fullName);
            userData.setEmail(email);
            
            // Save user to database
            userData = userService.upsertUser(userData);
            
            // Create IdPrincipal
            var idPrincipal = new IdPrincipal(userData.getId(), username, new java.util.ArrayList<>(authentication.getAuthorities()));
            
            // Update the authentication with IdPrincipal
            var newAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                idPrincipal, authentication.getCredentials(), authentication.getAuthorities());
            org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(newAuth);
            
            logger.info("User session created for: " + username);
        } else {
            String username = authentication.getName();
            logger.info("User authenticated with username: " + username);
        }
        
        // Return JSON success response
        response.setContentType("application/json");
        response.setStatus(200);
        response.getWriter().write("{\"success\":true}");
    }
}