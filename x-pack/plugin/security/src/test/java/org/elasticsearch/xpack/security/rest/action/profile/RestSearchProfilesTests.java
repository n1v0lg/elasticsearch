/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.rest.action.profile;

import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.test.rest.RestActionTestCase;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheRequest;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheResponse;
import org.elasticsearch.xpack.security.rest.action.service.RestClearServiceAccountTokenStoreCacheAction;
import org.junit.Before;

import java.util.concurrent.atomic.AtomicReference;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestSearchProfilesTests extends RestActionTestCase {
    private AtomicReference<ClearSecurityCacheRequest> requestHolder;

    @Before
    public void init() {
        Settings settings = Settings.builder().put(XPackSettings.SECURITY_ENABLED.getKey(), true).build();
        XPackLicenseState licenseState = mock(XPackLicenseState.class);
        requestHolder = new AtomicReference<>();
        controller().registerHandler(new RestClearServiceAccountTokenStoreCacheAction(settings, licenseState));
        verifyingClient.setExecuteVerifier(((actionType, actionRequest) -> {
            assertThat(actionRequest, instanceOf(ClearSecurityCacheRequest.class));
            requestHolder.set((ClearSecurityCacheRequest) actionRequest);
            final ClearSecurityCacheResponse response = mock(ClearSecurityCacheResponse.class);
            when(response.getClusterName()).thenReturn(new ClusterName(""));
            return response;
        }));
    }

    public void testInnerPrepareRequestWithEmptyTokenName() {
        final String namespace = randomAlphaOfLengthBetween(3, 8);
        final String service = randomAlphaOfLengthBetween(3, 8);
        final String name = randomFrom("", "*", "_all");
        final FakeRestRequest restRequest = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).withMethod(RestRequest.Method.POST)
            .withPath("/_security/service/" + namespace + "/" + service + "/credential/token/" + name + "/_clear_cache")
            .build();

        dispatchRequest(restRequest);

        final ClearSecurityCacheRequest clearSecurityCacheRequest = requestHolder.get();
        assertThat(clearSecurityCacheRequest.keys(), equalTo(new String[] { namespace + "/" + service + "/" }));
    }
}
