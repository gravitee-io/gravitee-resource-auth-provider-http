/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.authprovider.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.authprovider.http.configuration.HttpAuthenticationProviderResourceConfiguration;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.internal.CloseFuture;
import io.vertx.core.internal.ContextInternal;
import io.vertx.core.internal.VertxInternal;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

/**
 * Guards the shared-client workaround of {@link HttpAuthenticationProviderResource}: the clients of a stopped resource
 * must leave the close future of the event loop context that created them.
 */
class HttpAuthenticationProviderResourceClientRetentionTest {

    private static final int REDEPLOYS = 20;

    private Vertx vertx;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
    }

    @AfterEach
    void tearDown() throws Exception {
        vertx.close().await(10, TimeUnit.SECONDS);
    }

    @Test
    void should_not_retain_the_clients_of_stopped_resources() throws Exception {
        // Each iteration mimics an API redeploy: a new resource authenticates once on the event loop of the deployed
        // verticle, which creates its client, then is stopped.
        AtomicReference<CloseFuture> closeFuture = new AtomicReference<>();
        AtomicReference<Integer> before = new AtomicReference<>();

        vertx
            .deployVerticle(
                new AbstractVerticle() {
                    @Override
                    public void start() throws Exception {
                        closeFuture.set(((ContextInternal) context).closeFuture());
                        before.set(retained(closeFuture.get()));
                        for (int i = 0; i < REDEPLOYS; i++) {
                            HttpAuthenticationProviderResource resource = resource();
                            resource.start();
                            resource.authenticate("user", "password", mock(ExecutionContext.class, RETURNS_DEEP_STUBS), auth -> {});
                            resource.stop();
                        }
                    }
                }
            )
            .await(10, TimeUnit.SECONDS);

        assertThat(closeFuture.get()).isNotSameAs(((VertxInternal) vertx).closeFuture());
        awaitRetained(closeFuture.get(), before.get());
        assertThat(retained(closeFuture.get()) - before.get()).isZero();
    }

    @Test
    void should_still_leak_when_the_client_comes_straight_from_vertx() throws Exception {
        CloseFuture root = ((VertxInternal) vertx).closeFuture();
        int before = retained(root);

        for (int i = 0; i < REDEPLOYS; i++) {
            vertx.createHttpClient(new HttpClientOptions()).close().await(10, TimeUnit.SECONDS);
        }

        // When this starts failing, Vert.x has been fixed (5.2): drop the shared-client workaround and this test class.
        assertThat(retained(root) - before).isEqualTo(REDEPLOYS);
    }

    private HttpAuthenticationProviderResource resource() throws Exception {
        HttpAuthenticationProviderResourceConfiguration configuration = new HttpAuthenticationProviderResourceConfiguration();
        // Nothing listens there: the request fails, only the client creation matters.
        configuration.setUrl("http://localhost:1/auth");
        configuration.setMethod(io.gravitee.common.http.HttpMethod.POST);

        HttpAuthenticationProviderResource resource = new HttpAuthenticationProviderResource();
        Field field = AbstractConfigurableResource.class.getDeclaredField("configuration");
        field.setAccessible(true);
        field.set(resource, configuration);

        ApplicationContext applicationContext = mock(ApplicationContext.class);
        when(applicationContext.getBean(Node.class)).thenReturn(mock(Node.class));
        when(applicationContext.getBean(Vertx.class)).thenReturn(vertx);
        resource.setApplicationContext(applicationContext);
        return resource;
    }

    private static void awaitRetained(CloseFuture closeFuture, int expected) throws InterruptedException {
        // close() completes asynchronously, the nested close future unregisters itself once the client is closed.
        long deadline = System.currentTimeMillis() + 5_000;
        while (retained(closeFuture) != expected && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
    }

    private static int retained(CloseFuture closeFuture) {
        try {
            Field children = CloseFuture.class.getDeclaredField("children");
            children.setAccessible(true);
            Map<?, ?> map = (Map<?, ?>) children.get(closeFuture);
            return map == null ? 0 : map.size();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
