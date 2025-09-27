/** ******************************************************************************
 * Copyright (c) 2025 Precies. Software OU and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
import React, { FunctionComponent, ReactNode, useState, useEffect } from 'react';
import { Button, Dialog, DialogContent, DialogTitle, Stack, TextField, Box } from '@mui/material';

export const LoginComponent: FunctionComponent<LoginComponentProps> = (props) => {
    const [dialogOpen, setDialogOpen] = useState(false);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [csrfToken, setCsrfToken] = useState('');
    const [error, setError] = useState('');

    const showLoginDialog = () => setDialogOpen(true);

    useEffect(() => {
        // Fetch CSRF token when component mounts
        fetch('http://localhost:8080/user/csrf')
            .then(response => response.json())
            .then(data => {
                if (data.token) {
                    setCsrfToken(data.token);
                }
            })
            .catch(error => {
                console.warn('Failed to fetch CSRF token:', error);
                // Try without credentials for cross-origin request
                fetch('http://localhost:8080/user/csrf', { credentials: 'include' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.token) {
                            setCsrfToken(data.token);
                        }
                    })
                    .catch(err => console.warn('CSRF token fetch failed completely:', err));
            });
    }, []);

    const handleLdapLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        if (csrfToken) {
            formData.append('_csrf', csrfToken);
        }

        try {
            const response = await fetch('http://localhost:8080/login', {
                method: 'POST',
                body: formData,
                credentials: 'include'
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    setDialogOpen(false);
                    window.location.reload();
                }
            } else {
                const errorData = await response.json();
                setError(errorData.error || 'Login failed');
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('Network error occurred');
        }
    };

    const providers = Object.keys(props.loginProviders);
    const hasLdap = providers.indexOf('ldap') !== -1;
    const oauthProviders = providers.filter(p => p !== 'ldap');

    if (providers.length === 1 && !hasLdap) {
        return props.renderButton(props.loginProviders[providers[0]]);
    } else {
        return <>
            {props.renderButton(undefined, showLoginDialog)}
            <Dialog
                fullWidth
                open={dialogOpen}
                onClose={() => setDialogOpen(false)}
            >
                <DialogTitle>Log In</DialogTitle>
                <DialogContent>
                    <Stack spacing={2}>
                        {hasLdap && (
                            <Box component='form' onSubmit={handleLdapLogin}>
                                <Stack spacing={2}>
                                    {error && (
                                        <div style={{color: 'red', padding: '8px', backgroundColor: '#ffebee', borderRadius: '4px'}}>
                                            {error}
                                        </div>
                                    )}
                                    <TextField
                                        fullWidth
                                        label='Username'
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        required
                                    />
                                    <TextField
                                        fullWidth
                                        label='Password'
                                        type='password'
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                    <Button type='submit' fullWidth variant='contained' color='primary'>
                                        Login with LDAP
                                    </Button>
                                </Stack>
                            </Box>
                        )}
                        {oauthProviders.map((provider) => (
                            <Button
                                key={provider}
                                fullWidth
                                variant='contained'
                                color='secondary'
                                href={props.loginProviders[provider]}
                            >
                                Login with {provider}
                            </Button>
                        ))}
                    </Stack>
                </DialogContent>
            </Dialog>
        </>;
    }
};

export interface LoginComponentProps {
    loginProviders: Record<string, string>
    renderButton: (href?: string, onClick?: () => void) => ReactNode
}