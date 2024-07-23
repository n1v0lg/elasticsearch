/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package fixture.azure;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import org.elasticsearch.common.ssl.KeyStoreUtil;
import org.elasticsearch.common.ssl.PemUtils;
import org.elasticsearch.test.ESTestCase;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import static org.elasticsearch.test.ESTestCase.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class AzureHttpFixture extends ExternalResource {

    private final boolean enabled;
    private final String account;
    private final String container;
    private HttpsServer server;
    private HttpServer metadataServer;

    public AzureHttpFixture(boolean enabled, String account, String container) {
        this.enabled = enabled;
        this.account = account;
        this.container = container;
    }

    public String getAddress() {
        return "https://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + "/" + account;
    }

    public String getMetadataAddress() {
        return "http://" + metadataServer.getAddress().getHostString() + ":" + metadataServer.getAddress().getPort() + "/";
    }

    @Override
    protected void before() throws Exception {
        if (enabled) {

            try {
                this.metadataServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
                metadataServer.createContext("/", new AzureMetadataServiceHttpHandler());
                metadataServer.start();

                this.server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
                final var tmpdir = ESTestCase.createTempDir();
                final var certificates = PemUtils.readCertificates(List.of(copyResource(tmpdir, "azure-http-fixture.pem")));
                assertThat(certificates, hasSize(1));
                final SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(
                    new KeyManager[] {
                        KeyStoreUtil.createKeyManager(
                            new Certificate[] { certificates.get(0) },
                            PemUtils.readPrivateKey(copyResource(tmpdir, "azure-http-fixture.key"), () -> null),
                            null
                        ) },
                    null,
                    new SecureRandom()
                );
                server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
                server.createContext("/" + account, new AzureHttpHandler(account, container));
                server.start();
            } catch (Exception e) {
                throw new AssertionError("unexpected", e);
            }
        }
    }

    private Path copyResource(Path tmpdir, String name) throws IOException {
        try (
            var stream = Objects.requireNonNullElseGet(
                getClass().getResourceAsStream(name),
                () -> ESTestCase.fail(null, "resource [%s] not found", name)
            )
        ) {
            final var path = tmpdir.resolve(name);
            Files.write(path, stream.readAllBytes());
            return path;
        }
    }

    @Override
    protected void after() {
        if (enabled) {
            server.stop(0);
            metadataServer.stop(0);
        }
    }
}
