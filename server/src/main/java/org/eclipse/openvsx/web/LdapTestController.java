/********************************************************************************
 * Copyright (c) 2024 Eclipse Foundation and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.web;

import org.eclipse.openvsx.security.LdapConfig;
import org.eclipse.openvsx.security.LdapConnectionTest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@ConditionalOnProperty(name = "ovsx.ldap.url", matchIfMissing = false)
public class LdapTestController {

    private final LdapConfig ldapConfig;
    private final LdapConnectionTest ldapConnectionTest;

    public LdapTestController(LdapConfig ldapConfig, LdapConnectionTest ldapConnectionTest) {
        this.ldapConfig = ldapConfig;
        this.ldapConnectionTest = ldapConnectionTest;
    }

    @GetMapping("/ldap-test")
    public Map<String, Object> testLdapConnection() {
        Map<String, Object> result = new HashMap<>();
        result.put("ldapEnabled", ldapConfig.isLdapEnabled());
        
        if (ldapConfig.isLdapEnabled()) {
            try {
                boolean connected = ldapConnectionTest.testConnection();
                result.put("connectionTest", connected ? "SUCCESS" : "FAILED");
            } catch (Exception e) {
                result.put("connectionTest", "ERROR: " + e.getMessage());
            }
        }
        
        return result;
    }
}