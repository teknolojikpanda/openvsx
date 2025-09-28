/********************************************************************************
 * Copyright (c) 2025 Eclipse Foundation and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.publish;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class PublishConfig {

    @Value("${ovsx.publish.allowNamespaceAutoCreation:true}")
    private boolean allowNamespaceAutoCreation;

    public boolean isAllowNamespaceAutoCreation() {
        return allowNamespaceAutoCreation;
    }
}