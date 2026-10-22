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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.gravitee.el.TemplateContext;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.authprovider.http.configuration.HttpAuthenticationProviderResourceConfiguration;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.internal.CloseFuture;
import io.vertx.core.internal.ContextInternal;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

/**
 * Guards the shared-client workaround of {@link HttpAuthenticationProviderResource}: the clients of a stopped resource
 * must leave the close future of the event loop contexts that created them, once their connections are closed.
 */
class HttpAuthenticationProviderResourceClientRetentionTest {

    private static final int REDEPLOYS = 10;
    private static final int EVENT_LOOPS = 2;

    private Vertx vertx;
    private HttpServer server;
    private ExecutionContext executionContext;
    private final List<Context> eventLoops = new ArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        vertx = Vertx.vertx();
        server = vertx
            .createHttpServer()
            .requestHandler(request -> request.response().end("ok"))
            .listen(0, "localhost")
            .await(10, TimeUnit.SECONDS);

        // Let the success path run: the condition holds and the template context accepts the variables.
        TemplateEngine templateEngine = mock(TemplateEngine.class);
        when(templateEngine.getTemplateContext()).thenReturn(mock(TemplateContext.class));
        when(templateEngine.getValue(anyString(), eq(Boolean.class))).thenReturn(true);
        executionContext = mock(ExecutionContext.class);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);

        // Each verticle runs on its own event loop context, like the instances of the gateway HTTP server verticle.
        for (int i = 0; i < EVENT_LOOPS; i++) {
            Promise<Context> started = Promise.promise();
            vertx
                .deployVerticle(
                    new AbstractVerticle() {
                        @Override
                        public void start() {
                            started.complete(context);
                        }
                    }
                )
                .await(10, TimeUnit.SECONDS);
            eventLoops.add(started.future().await(10, TimeUnit.SECONDS));
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        vertx.close().await(10, TimeUnit.SECONDS);
    }

    @Test
    void should_not_retain_the_clients_of_stopped_resources() throws Exception {
        assertThat(eventLoops.get(0)).isNotSameAs(eventLoops.get(1));
        List<Integer> before = eventLoops
            .stream()
            .map(context -> retained(closeFuture(context)))
            .toList();
        AtomicInteger authenticated = new AtomicInteger();

        // Each iteration mimics an API redeploy: a new resource authenticates once on every event loop, which creates its
        // client and leaves a pooled connection open, then is stopped from another thread, as the deployer does.
        for (int i = 0; i < REDEPLOYS; i++) {
            HttpAuthenticationProviderResource resource = resource();
            resource.start();
            for (Context eventLoop : eventLoops) {
                onContext(eventLoop, () -> authenticate(resource)).await(10, TimeUnit.SECONDS);
                authenticated.incrementAndGet();
            }
            resource.stop();
        }

        // Without this the test would pass vacuously.
        assertThat(authenticated).hasValue(EVENT_LOOPS * REDEPLOYS);
        for (int i = 0; i < EVENT_LOOPS; i++) {
            CloseFuture closeFuture = closeFuture(eventLoops.get(i));
            assertThat(awaitRetained(closeFuture, before.get(i)) - before.get(i)).as("clients left on event loop %d", i).isZero();
        }
    }

    @Test
    void should_still_leak_when_the_client_comes_straight_from_vertx() throws Exception {
        // This watches the Vert.x version this module is built against (from gravitee-bom), not necessarily the one APIM
        // ships: when it starts failing, remove the workaround here once the gateway runs on the same Vert.x.
        Context eventLoop = eventLoops.get(0);
        int before = retained(closeFuture(eventLoop));

        for (int i = 0; i < REDEPLOYS; i++) {
            onContext(eventLoop, () -> vertx.createHttpClient(new HttpClientOptions()).close()).await(10, TimeUnit.SECONDS);
        }

        assertThat(retained(closeFuture(eventLoop)) - before)
            .as(
                "Vert.x no longer leaks closed clients: remove the shared-client workaround of HttpAuthenticationProviderResource and this test"
            )
            .isEqualTo(REDEPLOYS);
    }

    private Future<Void> authenticate(HttpAuthenticationProviderResource resource) {
        Promise<Void> done = Promise.promise();
        resource.authenticate("user", "password", executionContext, authentication -> {
            if (authentication != null) {
                done.complete();
            } else {
                done.fail("authentication failed");
            }
        });
        return done.future();
    }

    private HttpAuthenticationProviderResource resource() throws Exception {
        HttpAuthenticationProviderResourceConfiguration configuration = new HttpAuthenticationProviderResourceConfiguration();
        configuration.setUrl("http://localhost:" + server.actualPort() + "/auth");
        configuration.setMethod(io.gravitee.common.http.HttpMethod.POST);
        configuration.setCondition("{#authResponse.status == 200}");

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

    private static Future<Void> onContext(Context context, Supplier<Future<Void>> action) {
        Promise<Void> done = Promise.promise();
        context.runOnContext(v -> action.get().onComplete(done));
        return done.future();
    }

    private static CloseFuture closeFuture(Context context) {
        return ((ContextInternal) context).closeFuture();
    }

    /** Waits for close() to complete asynchronously and returns the last count observed. */
    private static int awaitRetained(CloseFuture closeFuture, int expected) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5_000;
        int retained = retained(closeFuture);
        while (retained != expected && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
            retained = retained(closeFuture);
        }
        return retained;
    }

    private static int retained(CloseFuture closeFuture) {
        try {
            Field children = CloseFuture.class.getDeclaredField("children");
            children.setAccessible(true);
            Map<?, ?> map = (Map<?, ?>) children.get(closeFuture);
            return map == null ? 0 : map.size();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "CloseFuture.children is gone: Vert.x internals changed, this does not mean the leak is fixed. " +
                    "Re-check how closed clients are tracked before touching the shared-client workaround.",
                e
            );
        }
    }
}
