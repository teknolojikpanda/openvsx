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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
@ConditionalOnProperty(name = "ovsx.ldap.url", matchIfMissing = false)
public class LdapConnectionTest {

    private static final Logger logger = LoggerFactory.getLogger(LdapConnectionTest.class);

    @Autowired
    private LdapTemplate ldapTemplate;

    @Value("${ovsx.ldap.userSearchBase:}")
    private String userSearchBase;

    @PostConstruct
    public void testLdapConnection() {
        testConnection();
    }
    
    public boolean testConnection() {
        try {
            logger.info("Testing LDAP connection and user search base...");
            
            // Test basic connection
            ldapTemplate.lookup("");
            logger.info("LDAP connection successful");
            
            // Test if user search base exists
            try {
                ldapTemplate.lookup(userSearchBase);
                logger.info("User search base '{}' exists and is accessible", userSearchBase);
                return true;
            } catch (Exception e) {
                logger.error("User search base '{}' does not exist or is not accessible: {}", userSearchBase, e.getMessage());
                logger.info("Please verify the LDAP directory structure and update ovsx.ldap.userSearchBase property");
                return false;
            }
            
        } catch (Exception e) {
            logger.error("LDAP connection test failed: {}", e.getMessage());
            logger.info("Please check LDAP server configuration and connectivity");
            return false;
        }
    }
}