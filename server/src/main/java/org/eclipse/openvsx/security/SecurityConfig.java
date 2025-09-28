/********************************************************************************
 * Copyright (c) 2020 TypeFox and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.security;

import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.annotation.PostConstruct;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${ovsx.webui.url:}")
    String webuiUrl;

    @Value("${ovsx.webui.frontendRoutes:/extension/**,/namespace/**,/user-settings/**,/admin-dashboard/**}")
    String[] frontendRoutes;

    @Value("${ovsx.ldap.userSearchBase:}")
    String ldapUserSearchBase;

    @Value("${ovsx.ldap.userSearchFilter:(uid={0})}")
    String ldapUserSearchFilter;

    @Value("${ovsx.ldap.groupSearchBase:}")
    String ldapGroupSearchBase;

    @Value("${ovsx.ldap.groupSearchFilter:(member=uid={0},{1},{2})}")
    String ldapGroupSearchFilter;

    @Value("${ovsx.ldap.adminGroups:admins,openvsx-admins}")
    String ldapAdminGroups;

    @Value("${ovsx.ldap.base:}")
    String ldapBase;

    private final LdapConfig ldapConfig;
    private final LdapUserService ldapUserService;
    private final org.eclipse.openvsx.UserService userService;
    private final org.springframework.ldap.core.LdapTemplate ldapTemplate;

    public SecurityConfig(LdapConfig ldapConfig, LdapUserService ldapUserService, org.eclipse.openvsx.UserService userService, org.springframework.ldap.core.LdapTemplate ldapTemplate) {
        this.ldapConfig = ldapConfig;
        this.ldapUserService = ldapUserService;
        this.userService = userService;
        this.ldapTemplate = ldapTemplate;
    }

    @PostConstruct
    public void logSecurityConfig() {
        logger.info("SecurityConfig - UserSearchBase: '{}', UserSearchFilter: '{}'", ldapUserSearchBase, ldapUserSearchFilter);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, OAuth2UserServices userServices) throws Exception {
        var filterChain = http.authorizeHttpRequests(
                registry -> registry
                        .requestMatchers(antMatchers("/*", "/login/**", "/oauth2/**", "/login-providers", "/user", "/user/auth-error", "/logout", "/ldap-test", "/actuator/health/**", "/actuator/metrics", "/actuator/metrics/**", "/actuator/prometheus", "/v3/api-docs/**", "/swagger-resources/**", "/swagger-ui/**", "/webjars/**"))
                            .permitAll()
                        .requestMatchers(antMatchers("/api/*/*/review", "/api/*/*/review/delete", "/api/user/publish", "/api/user/namespace/create"))
                            .authenticated()
                        .requestMatchers(antMatchers("/api/**", "/vscode/**", "/documents/**", "/admin/api/**", "/admin/report"))
                            .permitAll()
                        .requestMatchers(antMatchers("/admin/**"))
                            .hasAuthority("ROLE_ADMIN")
                        .requestMatchers(antMatchers(frontendRoutes))
                            .permitAll()
                        .anyRequest()
                            .authenticated()
                )
                .cors(configurer -> configurer.configurationSource(request -> {
                    var cors = new org.springframework.web.cors.CorsConfiguration();
                    cors.setAllowedOrigins(java.util.List.of("http://localhost:3000"));
                    cors.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    cors.setAllowedHeaders(java.util.List.of("*"));
                    cors.setAllowCredentials(true);
                    return cors;
                }))
                .csrf(configurer -> configurer.ignoringRequestMatchers(antMatchers("/api/-/publish", "/api/-/namespace/create", "/api/-/query", "/vscode/**", "/admin/api/**", "/login")))
                .exceptionHandling(configurer -> configurer.authenticationEntryPoint(new Http403ForbiddenEntryPoint()));

        // Configure LDAP authentication if enabled
        if (ldapConfig.isLdapEnabled()) {
            var redirectUrl = StringUtils.isEmpty(webuiUrl) ? "http://localhost:8080/" : webuiUrl;
            filterChain.formLogin(configurer -> {
                configurer.loginPage("/login")
                        .loginProcessingUrl("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(new LdapAuthenticationSuccessHandler(redirectUrl, userService, ldapTemplate, ldapUserSearchBase, ldapGroupSearchBase, ldapGroupSearchFilter, ldapAdminGroups, ldapBase))
                        .failureHandler((request, response, exception) -> {
                            logger.error("LDAP Authentication Failed: " + exception.getMessage());
                            response.setContentType("application/json");
                            response.setStatus(401);
                            response.getWriter().write("{\"error\":\"Invalid username or password\"}");
                        })
                        .permitAll();
            });
            try {
                filterChain.authenticationProvider(ldapAuthenticationProvider());
            } catch (Exception e) {
                logger.error("LDAP provider not available, skipping LDAP configuration: {}", e.getMessage());
            }
        }

        // Configure OAuth2 authentication if enabled
        if(userServices.canLogin()) {
            var redirectUrl = StringUtils.isEmpty(webuiUrl) ? "http://localhost:3000/" : webuiUrl;
            filterChain.oauth2Login(configurer -> {
                configurer.defaultSuccessUrl(redirectUrl);
                configurer.successHandler(new CustomAuthenticationSuccessHandler(redirectUrl));
                configurer.failureUrl(redirectUrl + "?auth-error");
                configurer.userInfoEndpoint(customizer -> customizer.oidcUserService(userServices.getOidc()).userService(userServices.getOauth2()));
            })
            .logout(configurer -> configurer.logoutSuccessUrl(redirectUrl));
        }

        return filterChain.build();
    }

    @Bean
    @ConditionalOnProperty(name = "ovsx.ldap.url", matchIfMissing = false)
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        try {
            logger.info("Creating LDAP authentication provider with userSearchBase: '{}', userSearchFilter: '{}'", ldapUserSearchBase, ldapUserSearchFilter);
            
            var contextSource = ldapConfig.contextSource();
            var authenticator = new BindAuthenticator(contextSource);
            
            if (ldapUserSearchBase != null && !ldapUserSearchBase.isEmpty()) {
                var userSearch = new FilterBasedLdapUserSearch(ldapUserSearchBase, ldapUserSearchFilter, contextSource);
                authenticator.setUserSearch(userSearch);
                logger.info("LDAP user search configured: base='{}', filter='{}'", ldapUserSearchBase, ldapUserSearchFilter);
            } else {
                logger.warn("LDAP userSearchBase is empty, using DN patterns instead");
                authenticator.setUserDnPatterns(new String[]{"uid={0}," + ldapUserSearchBase});
            }
            
            LdapAuthoritiesPopulator authoritiesPopulator = new LdapAuthoritiesPopulator() {
                @Override
                public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
                    try {
                        logger.debug("Loading authorities for LDAP user: {}", username);
                        UserDetails userDetails = ldapUserService.loadUserByUsername(username);
                        return userDetails.getAuthorities();
                    } catch (Exception e) {
                        logger.warn("Failed to load authorities for user '{}': {}", username, e.getMessage());
                        return java.util.Collections.emptyList();
                    }
                }
            };
            
            var provider = new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
            
            // Enable strict password comparison to prevent partial password acceptance
            provider.setUseAuthenticationRequestCredentials(true);
            
            logger.info("LDAP authentication provider created successfully with strict password validation");
            return provider;
        } catch (Exception e) {
            logger.error("Failed to create LDAP authentication provider: {}", e.getMessage(), e);
            throw e;
        }
    }

    private RequestMatcher[] antMatchers(String... patterns)
    {
        var antMatchers = new RequestMatcher[patterns.length];
        for(var i = 0; i < patterns.length; i++) {
            antMatchers[i] = AntPathRequestMatcher.antMatcher(patterns[i]);
        }

        return antMatchers;
    }
}