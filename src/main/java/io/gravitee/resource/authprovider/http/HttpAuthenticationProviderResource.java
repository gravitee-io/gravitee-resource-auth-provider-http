/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.authprovider.http;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.utils.UUID;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.http.configuration.HttpAuthenticationProviderResourceConfiguration;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class HttpAuthenticationProviderResource
    extends AuthenticationProviderResource<HttpAuthenticationProviderResourceConfiguration>
    implements ApplicationContextAware {

    private final Logger logger = LoggerFactory.getLogger(HttpAuthenticationProviderResource.class);

    private static final String HTTPS_SCHEME = "https";

    private Vertx vertx;

    private final Map<Context, HttpClient> httpClients = new HashMap<>();

    private HttpClientOptions httpClientOptions;

    private ApplicationContext applicationContext;

    private String userAgent;

    private static final String TEMPLATE_VARIABLE = "authResponse";

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        URL url = new URL(configuration().getUrl());

        int port = url.getPort() != -1 ? url.getPort() : (HTTPS_SCHEME.equals(url.getProtocol()) ? 443 : 80);

        // URI.getHost does not support '_' in the name, so we are using an intermediate URL to get the final host
        String host = url.getHost();

        httpClientOptions = new HttpClientOptions().setDefaultPort(port).setDefaultHost(host).setIdleTimeout(60).setConnectTimeout(10000);

        if (configuration().isUseSystemProxy()) {
            httpClientOptions.setProxyOptions(getSystemProxyOptions());
        }

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol())) {
            httpClientOptions.setSsl(true).setVerifyHost(false).setTrustAll(true);
        }

        userAgent = NodeUtils.userAgent(applicationContext.getBean(Node.class));
        vertx = applicationContext.getBean(Vertx.class);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        httpClients
            .values()
            .forEach(httpClient -> {
                try {
                    httpClient.close();
                } catch (IllegalStateException ise) {
                    logger.warn(ise.getMessage());
                }
            });
    }

    @Override
    public void authenticate(String username, String password, ExecutionContext context, Handler<Authentication> handler) {
        HttpClient httpClient = httpClients.computeIfAbsent(Vertx.currentContext(), __ -> vertx.createHttpClient(httpClientOptions));

        logger.debug("Authenticate user requesting {}", configuration().getUrl());

        HttpClientRequest request = httpClient
            .requestAbs(convert(configuration().getMethod()), configuration().getUrl())
            .handler(
                new io.vertx.core.Handler<HttpClientResponse>() {
                    @Override
                    public void handle(HttpClientResponse httpResponse) {
                        httpResponse.bodyHandler(
                            new io.vertx.core.Handler<Buffer>() {
                                @Override
                                public void handle(Buffer body) {
                                    TemplateEngine tplEngine = context.getTemplateEngine();

                                    // Put response into template variable for EL
                                    tplEngine
                                        .getTemplateContext()
                                        .setVariable(TEMPLATE_VARIABLE, new AuthenticationResponse(httpResponse, body.toString()));

                                    boolean success = tplEngine.getValue(configuration().getCondition(), Boolean.class);

                                    if (success) {
                                        handler.handle(new Authentication(username));
                                    } else {
                                        handler.handle(null);
                                    }
                                }
                            }
                        );
                    }
                }
            )
            .exceptionHandler(
                new io.vertx.core.Handler<Throwable>() {
                    @Override
                    public void handle(Throwable throwable) {
                        handler.handle(null);
                    }
                }
            );

        request.setTimeout(30000L);
        request.headers().add(HttpHeaders.USER_AGENT, userAgent);
        request.headers().add("X-Gravitee-Request-Id", UUID.toString(UUID.random()));

        context.getTemplateEngine().getTemplateContext().setVariable("username", username);
        context.getTemplateEngine().getTemplateContext().setVariable("password", password);

        // Merge headers with those from configuration and apply templating
        if (configuration().getHeaders() != null && !configuration().getHeaders().isEmpty()) {
            configuration()
                .getHeaders()
                .forEach(header ->
                    request.headers().add(header.getName(), context.getTemplateEngine().getValue(header.getValue(), String.class))
                );
        }

        if (configuration().getBody() != null && !configuration().getBody().isEmpty()) {
            String body = context.getTemplateEngine().getValue(configuration().getBody(), String.class);
            request.headers().remove(io.vertx.core.http.HttpHeaders.TRANSFER_ENCODING);
            request.putHeader(io.vertx.core.http.HttpHeaders.CONTENT_LENGTH, Integer.toString(body.length()));
            request.end(Buffer.buffer(body));
        } else {
            request.end();
        }
    }

    private ProxyOptions getSystemProxyOptions() {
        Environment environment = applicationContext.getEnvironment();

        StringBuilder errors = new StringBuilder();
        ProxyOptions proxyOptions = new ProxyOptions();

        // System proxy must be well configured. Check that this is the case.
        if (environment.containsProperty("system.proxy.host")) {
            proxyOptions.setHost(environment.getProperty("system.proxy.host"));
        } else {
            errors.append("'system.proxy.host' ");
        }

        try {
            proxyOptions.setPort(Integer.parseInt(Objects.requireNonNull(environment.getProperty("system.proxy.port"))));
        } catch (Exception e) {
            errors.append("'system.proxy.port' [").append(environment.getProperty("system.proxy.port")).append("] ");
        }

        try {
            proxyOptions.setType(ProxyType.valueOf(environment.getProperty("system.proxy.type")));
        } catch (Exception e) {
            errors.append("'system.proxy.type' [").append(environment.getProperty("system.proxy.type")).append("] ");
        }

        proxyOptions.setUsername(environment.getProperty("system.proxy.username"));
        proxyOptions.setPassword(environment.getProperty("system.proxy.password"));

        if (errors.length() == 0) {
            return proxyOptions;
        } else {
            logger.warn(
                "HTTP authentication provider requires a system proxy to be defined to call [{}] but some configurations are missing or not well defined: {}",
                configuration().getUrl(),
                errors
            );
            logger.warn("Ignoring system proxy");
            return null;
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    private HttpMethod convert(io.gravitee.common.http.HttpMethod httpMethod) {
        switch (httpMethod) {
            case CONNECT:
                return HttpMethod.CONNECT;
            case DELETE:
                return HttpMethod.DELETE;
            case GET:
                return HttpMethod.GET;
            case HEAD:
                return HttpMethod.HEAD;
            case OPTIONS:
                return HttpMethod.OPTIONS;
            case PATCH:
                return HttpMethod.PATCH;
            case POST:
                return HttpMethod.POST;
            case PUT:
                return HttpMethod.PUT;
            case TRACE:
                return HttpMethod.TRACE;
            case OTHER:
                return HttpMethod.OTHER;
        }

        return null;
    }
}
