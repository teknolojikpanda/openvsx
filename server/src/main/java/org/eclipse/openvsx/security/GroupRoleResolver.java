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

import org.eclipse.openvsx.entities.UserData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.AttributesMapper;

import javax.naming.directory.SearchControls;
import javax.naming.directory.Attributes;
import java.util.Optional;
import java.util.Set;

public class GroupRoleResolver {
    private static final Logger logger = LoggerFactory.getLogger(GroupRoleResolver.class);
    
    private final LdapTemplate ldap;
    private final String groupBase;
    private final String filterTpl;
    private final Set<String> adminGroups;

    public GroupRoleResolver(LdapTemplate ldap, String groupBase, String filterTpl, String adminGroupsCsv) {
        this.ldap = ldap;
        this.groupBase = groupBase;
        this.filterTpl = filterTpl;
        this.adminGroups = Set.of(adminGroupsCsv.split(","));
    }

    public String resolve(String username, String userSearchBase, String ldapBase) {
        try {
            String filter = filterTpl
                .replace("{0}", username)
                .replace("{1}", userSearchBase)
                .replace("{2}", ldapBase);
            var groups = ldap.search(groupBase, filter, mkControls(),
                (AttributesMapper<String>) attrs -> {
                    try {
                        var cnAttr = attrs.get("cn");
                        return cnAttr != null ? (String) cnAttr.get() : null;
                    } catch (Exception e) {
                        return null;
                    }
                });
            for (var g : groups) {
                if (g != null && adminGroups.contains(g.trim())) {
                    return UserData.ROLE_ADMIN;
                }
            }
        } catch (Exception e) {
            logger.warn("LDAP group lookup failed", e);
        }
        return UserData.ROLE_PRIVILEGED;
    }

    private SearchControls mkControls() {
        var sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setReturningAttributes(new String[]{"cn"});
        return sc;
    }
}