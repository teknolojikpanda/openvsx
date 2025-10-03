/** ******************************************************************************
 * Copyright (c) 2025 Precies. Software OU and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
import React, { FunctionComponent, ReactNode, useState } from 'react';
import { Button, Dialog, DialogContent, DialogTitle, Stack } from '@mui/material';
import { useCsrfToken } from '../hooks/useCsrfToken';
import { LdapLoginForm } from '../components/LdapLoginForm';

export const LoginComponent: FunctionComponent<LoginComponentProps> = ({ loginProviders, renderButton }) => {
    const [open, setOpen] = useState(false);
    useCsrfToken(); // Keep for compatibility

    const providers = Object.keys(loginProviders);
    const hasLdap = providers.indexOf('ldap') !== -1;
    const oauth = providers.filter(p => p !== 'ldap');

    if (providers.length === 1 && !hasLdap) {
        return renderButton(loginProviders[providers[0]]);
    }

    const onSuccess = () => {
        setOpen(false);
        window.location.reload();
    };

    return (
        <>
            {renderButton(undefined, () => setOpen(true))}
            <Dialog open={open} onClose={() => setOpen(false)} fullWidth>
                <DialogTitle>Log In</DialogTitle>
                <DialogContent>
                    <Stack spacing={2}>

                        {hasLdap && (
                            <LdapLoginForm
                                csrfToken=''
                                onSuccess={onSuccess}
                            />
                        )}
                        {oauth.map(p => (
                            <Button key={p} href={loginProviders[p]} fullWidth variant='contained'>
                                Login with {p}
                            </Button>
                        ))}
                    </Stack>
                </DialogContent>
            </Dialog>
        </>
    );
};

export interface LoginComponentProps {
    loginProviders: Record<string, string>
    renderButton: (href?: string, onClick?: () => void) => ReactNode
}