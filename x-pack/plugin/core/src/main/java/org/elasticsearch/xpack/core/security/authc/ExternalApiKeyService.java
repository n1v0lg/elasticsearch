/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authc;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.util.concurrent.ThreadContext;

public interface ExternalApiKeyService {
    AuthenticationToken extractCredentials(ThreadContext context);

    void authenticate(AuthenticationToken authenticationToken, ActionListener<AuthenticationResult<Authentication>> listener);

    class Noop implements ExternalApiKeyService {
        @Override
        public AuthenticationToken extractCredentials(ThreadContext context) {
            return null;
        }

        @Override
        public void authenticate(AuthenticationToken authenticationToken, ActionListener<AuthenticationResult<Authentication>> listener) {
            listener.onResponse(AuthenticationResult.notHandled());
        }
    }
}
