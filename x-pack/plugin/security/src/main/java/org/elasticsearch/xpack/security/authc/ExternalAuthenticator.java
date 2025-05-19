/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.ExternalApiKeyService;

public class ExternalAuthenticator implements Authenticator {
    private final ExternalApiKeyService service;

    public ExternalAuthenticator(ExternalApiKeyService service) {
        this.service = service;
    }

    @Override
    public String name() {
        return "";
    }

    @Override
    public AuthenticationToken extractCredentials(Context context) {
        return service.extractCredentials(context.getThreadContext());
    }

    @Override
    public void authenticate(Context context, ActionListener<AuthenticationResult<Authentication>> listener) {
        service.authenticate(context.getMostRecentAuthenticationToken(), listener);
    }
}
