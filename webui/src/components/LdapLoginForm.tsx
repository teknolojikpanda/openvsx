/** ******************************************************************************
 * Copyright (c) 2025 Precies. Software OU and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
import React, { useState } from 'react';
import { Box, Button, Stack, TextField } from '@mui/material';

interface Props {
    csrfToken: string;
    onSuccess: () => void;
}

export const LdapLoginForm: React.FC<Props> = ({ csrfToken, onSuccess }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        try {
            const url = window.location.origin;
            const res = await fetch(`${url}/login`, {
                method: 'POST',
                credentials: 'include',
                body: formData,
            });
            const payload = await res.json().catch(() => {
                throw new Error('Invalid JSON');
            });
            if (!res.ok || !payload.success) {
                throw new Error(payload.error || 'Login failed');
            }
            onSuccess();
        } catch (err: any) {
            console.error('LDAP login error:', err);
            // Map technical errors to generic user-facing messages
            let userMessage = 'Login failed. Please check your credentials and try again.';
            if (err?.response?.status === 401) {
                userMessage = 'Invalid username or password.';
            }
            setError(userMessage);
        }
    };

    return (
        <Box component='form' onSubmit={handleSubmit}>
            <Stack spacing={2}>
                {error && <div style={{ color: 'red' }}>{error}</div>}
                <TextField
                    fullWidth
                    label='Username'
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    required
                />
                <TextField
                    fullWidth
                    label='Password'
                    type='password'
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                />
                <Button type='submit' fullWidth variant='contained'>
                    Login with LDAP
                </Button>
            </Stack>
        </Box>
    );
};