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
    private final String userSearchBase;
    private final String groupSearchBase;
    private final String groupSearchFilter;
    private final String adminGroups;
    private final String ldapBase;

    public LdapAuthenticationSuccessHandler(String redirectUrl, org.eclipse.openvsx.UserService userService, 
                                          org.springframework.ldap.core.LdapTemplate ldapTemplate,
                                          String userSearchBase, String groupSearchBase, String groupSearchFilter, String adminGroups, String ldapBase) {
        this.redirectUrl = redirectUrl;
        this.userService = userService;
        this.ldapTemplate = ldapTemplate;
        this.userSearchBase = userSearchBase;
        this.groupSearchBase = groupSearchBase;
        this.groupSearchFilter = groupSearchFilter;
        this.adminGroups = adminGroups;
        this.ldapBase = ldapBase;
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
                    userSearchBase, 
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
            
            // Query LDAP groups for role assignment
            String role = determineUserRole(username);
            
            // Create user data for LDAP user
            var userData = new org.eclipse.openvsx.entities.UserData();
            userData.setLoginName(username);
            userData.setProvider("ldap");
            userData.setAuthId("ldap:" + username);
            userData.setFullName(fullName);
            userData.setEmail(email);
            userData.setRole(role);
            
            // Save user to database
            userData = userService.upsertUser(userData);
            
            // Create authorities based on user role
            var authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();
            if (org.eclipse.openvsx.entities.UserData.ROLE_ADMIN.equals(role)) {
                authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"));
            
            // Create IdPrincipal
            var idPrincipal = new IdPrincipal(userData.getId(), username, authorities);
            
            // Update the authentication with IdPrincipal
            var newAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                idPrincipal, authentication.getCredentials(), authorities);
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
    
    private String determineUserRole(String username) {
        try {
            // Search for groups the user belongs to
            var searchControls = new javax.naming.directory.SearchControls();
            searchControls.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[]{"cn"});
            
            String filter = groupSearchFilter.replace("{0}", username)
                                              .replace("{1}", userSearchBase)
                                              .replace("{2}", ldapBase);
            
            var groups = ldapTemplate.search(
                groupSearchBase,
                filter,
                searchControls,
                (org.springframework.ldap.core.AttributesMapper<String>) attrs -> {
                    return attrs.get("cn") != null ? (String) attrs.get("cn").get() : null;
                });
            
            // Check for admin groups first
            var adminGroupList = java.util.Arrays.asList(adminGroups.split(","));
            for (String adminGroup : adminGroupList) {
                if (groups.contains(adminGroup.trim())) {
                    logger.info("User {} assigned admin role based on group membership: {}", username, adminGroup.trim());
                    return org.eclipse.openvsx.entities.UserData.ROLE_ADMIN;
                }
            }
            
            logger.info("User {} assigned privileged role (default)", username);
            return org.eclipse.openvsx.entities.UserData.ROLE_PRIVILEGED;
            
        } catch (Exception e) {
            logger.warn("Could not query LDAP groups for user {}: {}", username, e.getMessage());
            return org.eclipse.openvsx.entities.UserData.ROLE_PRIVILEGED; // default role
        }
    }
}