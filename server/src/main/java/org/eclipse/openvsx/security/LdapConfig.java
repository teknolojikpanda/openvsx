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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.annotation.PostConstruct;

@Configuration
public class LdapConfig {

    private static final Logger logger = LoggerFactory.getLogger(LdapConfig.class);

    @Value("${ovsx.ldap.url:}")
    private String ldapUrl;

    @Value("${ovsx.ldap.base:}")
    private String ldapBase;

    @Value("${ovsx.ldap.userDn:}")
    private String ldapUserDn;

    @Value("${ovsx.ldap.password:}")
    private String ldapPassword;

    @Bean
    @ConditionalOnProperty(name = "ovsx.ldap.url", matchIfMissing = false)
    public LdapContextSource contextSource() {
        try {
            DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldapUrl);
            contextSource.setBase(ldapBase);
            if (!ldapUserDn.isEmpty() && !ldapPassword.isEmpty()) {
                contextSource.setUserDn(ldapUserDn);
                contextSource.setPassword(ldapPassword);
            }
            logger.info("LDAP Context Source created successfully for URL: {}", ldapUrl);
            return contextSource;
        } catch (Exception e) {
            logger.error("Failed to create LDAP context source for URL '{}': {}", ldapUrl, e.getMessage());
            throw e;
        }
    }

    @Bean
    @ConditionalOnProperty(name = "ovsx.ldap.url", matchIfMissing = false)
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }

    @PostConstruct
    public void logLdapConfig() {
        logger.info("LDAP Configuration - URL: '{}', Base: '{}', Enabled: {}", ldapUrl, ldapBase, isLdapEnabled());
    }

    public boolean isLdapEnabled() {
        boolean enabled = !ldapUrl.isEmpty() && !ldapBase.isEmpty();
        logger.debug("LDAP enabled check: URL='{}', Base='{}', Result={}", ldapUrl, ldapBase, enabled);
        return enabled;
    }
}