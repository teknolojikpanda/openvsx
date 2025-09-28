/********************************************************************************
 * Copyright (c) 2020 TypeFox and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.IndexOperations;
import org.mockito.Mockito;

@Configuration
@Profile("test")
public class TestSearchConfig {

    @Bean
    public ElasticsearchOperations elasticsearchOperations() {
        ElasticsearchOperations mock = Mockito.mock(ElasticsearchOperations.class);
        IndexOperations indexOps = Mockito.mock(IndexOperations.class);
        
        Mockito.when(mock.indexOps(Mockito.any(Class.class))).thenReturn(indexOps);
        Mockito.when(indexOps.exists()).thenReturn(false);
        Mockito.when(indexOps.create()).thenReturn(true);
        
        return mock;
    }
}