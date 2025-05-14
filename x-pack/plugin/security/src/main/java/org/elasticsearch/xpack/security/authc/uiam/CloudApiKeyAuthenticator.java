/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.uiam;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.authc.Authenticator;

import java.util.Map;
import java.util.Objects;

public class CloudApiKeyAuthenticator implements Authenticator {
    private static final Logger logger = LogManager.getLogger(CloudApiKeyAuthenticator.class);

    private final UiamClient client;
    private final ProjectInfoProvider projectInfoProvider;

    public CloudApiKeyAuthenticator(UiamClient client, ProjectInfoProvider projectInfoProvider) {
        this.client = client;
        this.projectInfoProvider = projectInfoProvider;
    }

    record CloudApiKey(SecureString rawHeader) implements AuthenticationToken {
        @Override
        public String principal() {
            return "<unauthenticated cloud api key>";
        }

        @Override
        public Object credentials() {
            return rawHeader;
        }

        @Override
        public void clearCredentials() {
            rawHeader.close();
        }
    }

    @Override
    public String name() {
        return "cloud api key";
    }

    @Override
    public AuthenticationToken extractCredentials(Context context) {
        SecureString extracted = Authenticator.extractCloudApiKeyFromHeader(context.getThreadContext());
        if (extracted == null) {
            logger.debug("No Cloud API Key found in the request");
            return null;
        }
        logger.info("Cloud API Key found");
        return new CloudApiKey(extracted);
    }

    @Override
    public void authenticate(Context context, ActionListener<AuthenticationResult<Authentication>> listener) {
        final AuthenticationToken authenticationToken = context.getMostRecentAuthenticationToken();
        if (false == authenticationToken instanceof CloudApiKey) {
            listener.onResponse(AuthenticationResult.notHandled());
            return;
        }

        logger.info("Authenticating with Cloud API Key");

        final ProjectInfoProvider.ProjectInfo projectInfo = projectInfoProvider.get();

        client.authenticateProject(
            new UiamClient.Request(
                projectInfo.projectId(),
                projectInfo.organizationId(),
                projectInfo.projectType(),
                (SecureString) authenticationToken.credentials()
            ),
            new ActionListener<>() {
                @Override
                public void onResponse(AuthenticateProjectApiKeyResponse response) {
                    assert Objects.equals(projectInfo.organizationId(), response.organizationId()) : "org ID mismatch";
                    logger.info("Got response from Cloud API Key authentication [{}]", response);
                    listener.onResponse(
                        AuthenticationResult.success(
                            Authentication.newCloudApiKeyAuthentication(
                                AuthenticationResult.success(
                                    new User(response.id(), response.applicationRoles().toArray(new String[0])),
                                    Map.of(
                                        "_security_cloud_serverless_project_id",
                                        projectInfo.projectId(),
                                        "_security_cloud_serverless_project_type",
                                        projectInfo.projectType(),
                                        "_security_cloud_serverless_organization_id",
                                        response.organizationId()
                                    )
                                ),
                                "node"
                            )
                        )
                    );
                }

                @Override
                public void onFailure(Exception e) {
                    logger.error("Failed authenticate project API call", e);
                    listener.onFailure(e);
                }
            }
        );
    }
}
