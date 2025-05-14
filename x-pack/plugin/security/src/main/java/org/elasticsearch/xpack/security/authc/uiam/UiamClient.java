/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.uiam;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.conn.NoopIOSessionStrategy;
import org.apache.http.nio.conn.SchemeIOSessionStrategy;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.core.Strings;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentType;

import java.io.InputStream;
import java.net.URI;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class UiamClient {

    private static final Logger logger = LogManager.getLogger(UiamClient.class);

    private static final String UIAM_SERVICE_HOST = "http://localhost:8080";

    private final CloseableHttpAsyncClient httpClient;

    public UiamClient(CloseableHttpAsyncClient httpClient) {
        this.httpClient = httpClient;
    }

    public void authenticateProject(Request request, ActionListener<AuthenticateProjectApiKeyResponse> listener) {
        doAuthenticateProject(request.toHttpRequest(), listener);
    }

    public void doAuthenticateProject(final HttpUriRequest request, ActionListener<AuthenticateProjectApiKeyResponse> listener) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            httpClient.execute(request, new FutureCallback<>() {
                @Override
                public void completed(final HttpResponse result) {
                    final StatusLine statusLine = result.getStatusLine();
                    final int statusCode = statusLine.getStatusCode();
                    if (statusCode == 200) {
                        final HttpEntity entity = result.getEntity();
                        try (InputStream inputStream = entity.getContent()) {
                            try (
                                XContentParser parser = XContentHelper.createParserNotCompressed(
                                    LoggingDeprecationHandler.XCONTENT_PARSER_CONFIG,
                                    new BytesArray(inputStream.readAllBytes()),
                                    XContentType.JSON
                                )
                            ) {
                                listener.onResponse(AuthenticateProjectApiKeyResponse.fromXContent(parser));
                            }
                        } catch (Exception e) {
                            listener.onFailure(e);
                        }
                    } else {
                        listener.onFailure(
                            new ElasticsearchSecurityException(
                                "Request failed, status [" + statusCode + "], reason [" + statusLine.getReasonPhrase() + "]."
                            )
                        );
                    }
                }

                @Override
                public void failed(Exception e) {
                    listener.onFailure(new ElasticsearchSecurityException("Request failed.", e));
                }

                @Override
                public void cancelled() {
                    listener.onFailure(new ElasticsearchSecurityException("Request was cancelled."));
                }
            });
            return null;
        });
    }

    public record Request(String projectId, String projectOwner, String projectType, SecureString credentials) {
        HttpUriRequest toHttpRequest() {
            HttpGet request = new HttpGet(URI.create(buildRequestPath()));
            request.addHeader("Authorization", "ApiKey " + credentials.toString());
            return request;
        }

        private String buildRequestPath() {
            return Strings.format(
                UIAM_SERVICE_HOST
                    + "/uiam/api/v1/authentication/"
                    + "_authenticate-project?include_token=false&project_id=%s&project_owner=%s&project_type=%s",
                projectId,
                projectOwner,
                projectType
            );
        }
    }

    public static CloseableHttpAsyncClient create() {
        try {
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedExceptionAction<CloseableHttpAsyncClient>) () -> {
                final ConnectingIOReactor ioReactor = new DefaultConnectingIOReactor();
                // final String sslKey = RealmSettings.realmSslPrefix(realmConfig.identifier());
                // final SslConfiguration sslConfiguration = sslService.getSSLConfiguration(sslKey);
                // final SSLContext clientContext = sslService.sslContext(sslConfiguration);
                // final HostnameVerifier verifier = SSLService.getHostnameVerifier(sslConfiguration);
                final Registry<SchemeIOSessionStrategy> registry = RegistryBuilder.<SchemeIOSessionStrategy>create()
                    .register("http", NoopIOSessionStrategy.INSTANCE)
                    // .register("https", new SSLIOSessionStrategy(clientContext, verifier))
                    .build();
                final PoolingNHttpClientConnectionManager connectionManager = new PoolingNHttpClientConnectionManager(ioReactor, registry);
                connectionManager.setDefaultMaxPerRoute(200);
                connectionManager.setMaxTotal(200);
                final RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(Math.toIntExact(TimeValue.timeValueSeconds(5).getMillis()))
                    .setConnectionRequestTimeout(Math.toIntExact(TimeValue.timeValueSeconds(5).getMillis()))
                    .setSocketTimeout(Math.toIntExact(TimeValue.timeValueSeconds(5).getMillis()))
                    .build();
                final HttpAsyncClientBuilder httpAsyncClientBuilder = HttpAsyncClients.custom()
                    .setConnectionManager(connectionManager)
                    .setDefaultRequestConfig(requestConfig);
                final CloseableHttpAsyncClient httpAsyncClient = httpAsyncClientBuilder.build();
                httpAsyncClient.start();
                return httpAsyncClient;
            });
        } catch (PrivilegedActionException e) {
            throw new IllegalStateException("Unable to create a HttpAsyncClient instance", e);
        }
    }
}
