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

    public UserAttributes map(String username) {
        try {
            var results = ldap.search(
                base,
                "(uid=" + username + ")",
                searchControls(),
                (AttributesMapper<String[]>) attrs -> {
                    String displayName = null;
                    try {
                        var attr = attrs.get("displayName");
                        if (attr != null) {
                            displayName = (String) attr.get();
                        }
                    } catch (Exception e) {
                        // Ignore attribute access errors
                    }
                    String fullNameResult = username;
                    if (displayName != null && !displayName.trim().isEmpty()) {
                        fullNameResult = displayName;
                    } else {
                        String givenName = null;
                        String surname = null;
                        try {
                            var givenAttr = attrs.get("givenName");
                            if (givenAttr != null) givenName = (String) givenAttr.get();
                            var snAttr = attrs.get("sn");
                            if (snAttr != null) surname = (String) snAttr.get();
                        } catch (Exception e) {
                            // Ignore attribute access errors
                        }
                        if (givenName != null && surname != null) {
                            fullNameResult = givenName + " " + surname;
                        } else {
                            String cn = null;
                            try {
                                var cnAttr = attrs.get("cn");
                                if (cnAttr != null) cn = (String) cnAttr.get();
                            } catch (Exception e) {
                                // Ignore attribute access errors
                            }
                            if (cn != null && !cn.equals(username)) {
                                fullNameResult = cn;
                            }
                        }
                    }
                    
                    String mail = username + "@company.com";
                    try {
                        var mailAttr = attrs.get("mail");
                        if (mailAttr != null) {
                            mail = (String) mailAttr.get();
                        } else {
                            var emailAttr = attrs.get("email");
                            if (emailAttr != null) {
                                mail = (String) emailAttr.get();
                            }
                        }
                    } catch (Exception e) {
                        // Use fallback email
                    }
                    return new String[]{fullNameResult, mail};
                }
            );
            if (!results.isEmpty() && results.get(0) != null) {
                var arr = results.get(0);
                return new UserAttributes(arr[0], arr[1]);
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