/********************************************************************************
 * Copyright (c) 2025 Eclipse Foundation and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.AttributesMapper;

import javax.naming.directory.SearchControls;
import javax.naming.directory.Attributes;
import java.util.Optional;

public class UserAttributesMapper {
    private static final Logger logger = LoggerFactory.getLogger(UserAttributesMapper.class);
    
    private final LdapTemplate ldap;
    private final String base;

    public UserAttributesMapper(LdapTemplate ldap, String base) {
        this.ldap = ldap;
        this.base = base;
    }

    public static class UserAttributes {
        private final String fullName;
        private final String email;
        
        public UserAttributes(String fullName, String email) {
            this.fullName = fullName;
            this.email = email;
        }
        
        public String fullName() { return fullName; }
        public String email() { return email; }
    }

    private Optional<String> safeGet(Attributes attrs, String name) {
        try {
            var a = attrs.get(name);
            return (a != null) ? Optional.ofNullable((String) a.get()) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private String extractFullName(Attributes attrs, String username) {
        return safeGet(attrs, "displayName")
            .filter(s -> !s.isBlank())
            .or(() -> safeGet(attrs, "givenName")
                .flatMap(given -> safeGet(attrs, "sn")
                    .map(sn -> given + " " + sn)))
            .or(() -> safeGet(attrs, "cn")
                .filter(cn -> !cn.equals(username)))
            .orElse(username);
    }

    public UserAttributes map(String username) {
        try {
            var results = ldap.search(
                base,
                "(uid=" + username + ")",
                searchControls(),
                (AttributesMapper<UserAttributes>) attrs -> {
                    String fullName = extractFullName(attrs, username);
                    String email = java.util.stream.Stream.of("mail", "email")
                        .map(attr -> safeGet(attrs, attr))
                        .flatMap(Optional::stream)
                        .findFirst()
                        .orElse(username + "@company.com");
                    return new UserAttributes(fullName, email);
                }
            );
            if (!results.isEmpty()) {
                return results.get(0);
            }
        } catch (Exception e) {
            logger.warn("LDAP attr lookup failed", e);
        }
        return new UserAttributes(username, username + "@company.com");
    }

    private SearchControls searchControls() {
        var sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setReturningAttributes(new String[]{"displayName", "givenName", "sn", "cn", "mail", "email"});
        return sc;
    }
}