/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.smoketest;

import io.netty.util.ThreadDeathWatcher;
import io.netty.util.concurrent.GlobalEventExecutor;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.PathUtils;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.elasticsearch.test.rest.ObjectPath;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

/**
 * This test checks that a Monitoring's HTTP exporter correctly exports to a monitoring cluster
 * protected by security with HTTPS/SSL.
 *
 * It sets up a cluster with Monitoring and Security configured with SSL. Once started,
 * an HTTP exporter is activated and it exports data locally over HTTPS/SSL. The test
 * then uses a rest client to check that the data have been correctly received and
 * indexed in the cluster.
 */
@SuppressWarnings("removal")
public class SmokeTestMonitoringWithSecurityIT extends ESRestTestCase {

    public class TestRestHighLevelClient extends RestHighLevelClient {
        TestRestHighLevelClient() {
            super(client(), RestClient::close, Collections.emptyList());
        }
    }

    /**
     * A JUnit class level rule that runs after the AfterClass method in {@link ESIntegTestCase},
     * which stops the cluster. After the cluster is stopped, there are a few netty threads that
     * can linger, so we wait for them to finish otherwise these lingering threads can intermittently
     * trigger the thread leak detector
     */
    @ClassRule
    public static final ExternalResource STOP_NETTY_RESOURCE = new ExternalResource() {
        @Override
        protected void after() {
            try {
                GlobalEventExecutor.INSTANCE.awaitInactivity(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IllegalStateException e) {
                if (e.getMessage().equals("thread was not started") == false) {
                    throw e;
                }
                // ignore since the thread was never started
            }

            try {
                ThreadDeathWatcher.awaitInactivity(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    };

    private static final String USER = "test_user";
    private static final SecureString PASS = new SecureString("x-pack-test-password".toCharArray());
    private static final String KEYSTORE_PASS = "testnode";
    private static final String MONITORING_PATTERN = ".monitoring-*";

    static Path keyStore;

    @BeforeClass
    public static void getKeyStore() {
        try {
            keyStore = PathUtils.get(SmokeTestMonitoringWithSecurityIT.class.getResource("/testnode.jks").toURI());
        } catch (URISyntaxException e) {
            throw new ElasticsearchException("exception while reading the store", e);
        }
        if (Files.exists(keyStore) == false) {
            throw new IllegalStateException("Keystore file [" + keyStore + "] does not exist.");
        }
    }

    @AfterClass
    public static void clearKeyStore() {
        keyStore = null;
    }

    RestHighLevelClient newHighLevelClient() {
        return new TestRestHighLevelClient();
    }

    @Override
    protected String getProtocol() {
        return "https";
    }

    @Override
    protected Settings restClientSettings() {
        String token = basicAuthHeaderValue(USER, PASS);
        return Settings.builder()
            .put(ThreadContext.PREFIX + ".Authorization", token)
            .put(ESRestTestCase.TRUSTSTORE_PATH, keyStore)
            .put(ESRestTestCase.TRUSTSTORE_PASSWORD, KEYSTORE_PASS)
            .build();
    }

    @Before
    public void enableExporter() throws Exception {
        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString("xpack.monitoring.exporters._http.auth.secure_password", "x-pack-test-password");
        Settings exporterSettings = Settings.builder()
            .put("xpack.monitoring.collection.enabled", true)
            .put("xpack.monitoring.exporters._http.enabled", true)
            .put("xpack.monitoring.exporters._http.type", "http")
            .put("xpack.monitoring.exporters._http.host", "https://" + randomNodeHttpAddress())
            .put("xpack.monitoring.exporters._http.auth.username", "monitoring_agent")
            .put("xpack.monitoring.exporters._http.ssl.verification_mode", "full")
            .put("xpack.monitoring.exporters._http.ssl.certificate_authorities", "testnode.crt")
            .setSecureSettings(secureSettings)
            .build();
        updateClusterSettings(exporterSettings);
    }

    @After
    public void disableExporter() throws IOException {
        Settings exporterSettings = Settings.builder()
            .putNull("xpack.monitoring.collection.enabled")
            .putNull("xpack.monitoring.exporters._http.enabled")
            .putNull("xpack.monitoring.exporters._http.type")
            .putNull("xpack.monitoring.exporters._http.host")
            .putNull("xpack.monitoring.exporters._http.auth.username")
            .putNull("xpack.monitoring.exporters._http.ssl.verification_mode")
            .putNull("xpack.monitoring.exporters._http.ssl.certificate_authorities")
            .build();
        updateClusterSettings(exporterSettings);
    }

    @SuppressWarnings("unchecked")
    private boolean getMonitoringUsageExportersDefined() throws Exception {
        Map<String, Object> monitoringUsage = (Map<String, Object>) getAsMap("/_xpack/usage").get("monitoring");
        assertThat("Monitoring feature set does not exist", monitoringUsage, notNullValue());

        @SuppressWarnings("unchecked")
        Map<String, Object> exporters = (Map<String, Object>) monitoringUsage.get("enabled_exporters");
        return exporters != null && exporters.isEmpty() == false;
    }

    @AwaitsFix(bugUrl = "https://github.com/elastic/elasticsearch/issues/49094")
    public void testHTTPExporterWithSSL() throws Exception {
        // Ensures that the exporter is actually on
        assertBusy(() -> assertThat("[_http] exporter is not defined", getMonitoringUsageExportersDefined(), is(true)));

        RestHighLevelClient client = newHighLevelClient();
        // Checks that the monitoring index templates have been installed
        Request templateRequest = new Request("GET", "/_index_template/" + MONITORING_PATTERN);
        assertBusy(() -> {
            try {
                var response = responseAsMap(client.getLowLevelClient().performRequest(templateRequest));
                List<?> templates = ObjectPath.evaluate(response, "index_templates");
                assertThat(templates.size(), greaterThanOrEqualTo(2));
            } catch (Exception e) {
                fail("template not ready yet: " + e.getMessage());
            }
        });

        Request indexRequest = new Request("HEAD", MONITORING_PATTERN);
        // Waits for monitoring indices to be created
        assertBusy(() -> {
            try {
                Response response = client.getLowLevelClient().performRequest(indexRequest);
                assertThat(response.getStatusLine().getStatusCode(), equalTo(200));
            } catch (Exception e) {
                fail("monitoring index not created yet: " + e.getMessage());
            }
        });

        // Waits for indices to be ready
        ensureHealth(MONITORING_PATTERN, (request) -> {
            request.addParameter("wait_for_status", "yellow");
            request.addParameter("wait_for_events", "languid");
            request.addParameter("wait_for_no_relocating_shards", "true");
            request.addParameter("wait_for_no_initializing_shards", "true");
        });

        // Checks that the HTTP exporter has successfully exported some data
        SearchRequest searchRequest = new SearchRequest(new String[] { MONITORING_PATTERN }, new SearchSourceBuilder().size(0));
        assertBusy(() -> {
            try {
                assertThat(client.search(searchRequest, RequestOptions.DEFAULT).getHits().getTotalHits().value, greaterThan(0L));
            } catch (Exception e) {
                fail("monitoring date not exported yet: " + e.getMessage());
            }
        });
    }

    @AwaitsFix(bugUrl = "https://github.com/elastic/elasticsearch/issues/49094")
    public void testSettingsFilter() throws IOException {
        final Request request = new Request("GET", "/_cluster/settings");
        final Response response = client().performRequest(request);
        final ObjectPath path = ObjectPath.createFromResponse(response);
        final Map<String, Object> settings = path.evaluate("transient.xpack.monitoring.exporters._http");
        assertThat(settings, hasKey("type"));
        assertThat(settings, not(hasKey("auth")));
        assertThat(settings, not(hasKey("ssl")));
    }

    @SuppressWarnings("unchecked")
    private String randomNodeHttpAddress() throws IOException {
        Response response = client().performRequest(new Request("GET", "/_nodes"));
        assertOK(response);
        ObjectPath objectPath = ObjectPath.createFromResponse(response);
        Map<String, Object> nodesAsMap = objectPath.evaluate("nodes");
        List<String> httpAddresses = new ArrayList<>();
        for (Map.Entry<String, Object> entry : nodesAsMap.entrySet()) {
            Map<String, Object> nodeDetails = (Map<String, Object>) entry.getValue();
            Map<String, Object> httpInfo = (Map<String, Object>) nodeDetails.get("http");
            httpAddresses.add((String) httpInfo.get("publish_address"));
        }
        assertThat(httpAddresses.size(), greaterThan(0));
        return randomFrom(httpAddresses);
    }
}
