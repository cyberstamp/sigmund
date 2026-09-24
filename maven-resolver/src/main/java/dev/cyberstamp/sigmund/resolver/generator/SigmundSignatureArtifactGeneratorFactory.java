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
package dev.cyberstamp.sigmund.resolver.generator;

import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.aether.spi.artifact.ArtifactPredicateFactory;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.eclipse.aether.spi.artifact.generator.ArtifactGeneratorFactory;
import org.eclipse.aether.util.ConfigUtils;

@Singleton
@Named(SigmundSignatureArtifactGeneratorFactory.NAME)
public final class SigmundSignatureArtifactGeneratorFactory implements ArtifactGeneratorFactory {

    public static final String NAME = "sigmund";

    private final ArtifactPredicateFactory artifactPredicateFactory;

    @Inject
    public SigmundSignatureArtifactGeneratorFactory(ArtifactPredicateFactory artifactPredicateFactory) {
        this.artifactPredicateFactory = artifactPredicateFactory;
    }

    /**
     * Signatures are not generated on install, only on deploy.
     */
    @Override
    public ArtifactGenerator newInstance(RepositorySystemSession session, InstallRequest request) {
        return null;
    }

    @Override
    public ArtifactGenerator newInstance(RepositorySystemSession session, DeployRequest request) {
        final boolean enabled = ConfigUtils.getBoolean(
                session, SigmundConfigurationKeys.DEFAULT_ENABLED, SigmundConfigurationKeys.CONFIG_PROP_ENABLED);
        if (!enabled) {
            return null;
        }

        return new SigmundSignatureArtifactGenerator(
                request.getArtifacts(), artifactPredicateFactory.newInstance(session)::hasChecksums);
    }

    /**
     * This generator should be usually the right-most in pipeline.
     */
    private float priority = 20000;

    @Override
    public float getPriority() {
        return priority;
    }

    public SigmundSignatureArtifactGeneratorFactory setPriority(float priority) {
        this.priority = priority;
        return this;
    }
}
