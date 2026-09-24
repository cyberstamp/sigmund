/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package dev.cyberstamp.sigmund.resolver.connector;

import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import javax.inject.Inject;
import javax.inject.Named;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.PipelineRepositoryConnectorFactory;
import org.eclipse.aether.spi.connector.RepositoryConnector;
import org.eclipse.aether.util.ConfigUtils;

@Named(SigmundPipelineRepositoryConnectorFactory.NAME)
public final class SigmundPipelineRepositoryConnectorFactory implements PipelineRepositoryConnectorFactory {
    public static final String NAME = "sigmund";

    /**
     * This connector should be usually the right-most in pipeline.
     */
    private float priority = 20000;

    @Inject
    public SigmundPipelineRepositoryConnectorFactory() {
    }

    @Override
    public RepositoryConnector newInstance(
            RepositorySystemSession session, RemoteRepository repository, RepositoryConnector delegate) {
        final boolean enabled = ConfigUtils.getBoolean(
                session, SigmundConfigurationKeys.DEFAULT_ENABLED, SigmundConfigurationKeys.CONFIG_PROP_ENABLED);
        if (enabled) {
            return new SigmundRepositoryConnector(session, repository, delegate);
        } else {
            return delegate;
        }
    }

    @Override
    public float getPriority() {
        return priority;
    }

    public SigmundPipelineRepositoryConnectorFactory setPriority(float priority) {
        this.priority = priority;
        return this;
    }
}
