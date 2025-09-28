/** ******************************************************************************
 * Copyright (c) 2025 Precies. Software OU and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
import { useState, useEffect } from 'react';

export function useCsrfToken() {
    const [token, setToken] = useState<string>('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string>('');

    useEffect(() => {
        const url = (process as any).env.REACT_APP_SERVER_URL || window.location.origin;
        
        async function fetchToken(opts?: RequestInit) {
            try {
                const res = await fetch(`${url}/user/csrf`, opts);
                const body = await res.json();
                if (body.token) {
                    setToken(body.token);
                    setError('');
                } else {
                    setError('Failed to retrieve CSRF token from server.');
                }
                setLoading(false);
            } catch (err) {
                if (!opts?.credentials) {
                    // Try with credentials for cross-origin request
                    fetchToken({ credentials: 'include' });
                } else {
                    setError('Unable to fetch CSRF token. Please try again later.');
                    setLoading(false);
                }
            }
        }
        
        fetchToken();
    }, []);

    return { token, loading, error };
}