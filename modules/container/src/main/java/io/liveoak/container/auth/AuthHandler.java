/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.auth;

import io.liveoak.container.DefaultRequestContext;
import io.liveoak.container.DefaultSecurityContext;
import io.liveoak.container.DirectConnector;
import io.liveoak.container.ResourceErrorResponse;
import io.liveoak.container.ResourceRequest;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourceException;
import io.liveoak.spi.SecurityContext;
import io.liveoak.spi.state.ResourceState;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpHeaders;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthHandler extends SimpleChannelInboundHandler<ResourceRequest> {

    public static final String AUTH_TYPE = "bearer";

    private DirectConnector connector;

    public AuthHandler(DirectConnector connector) {
        this.connector = connector;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ResourceRequest req) throws Exception {
        String auth = req.requestAttributes().getAttribute(HttpHeaders.Names.AUTHORIZATION, String.class);
        if (auth != null) {
            String[] split = auth.split(" ");
            if (split[0].toLowerCase().equals(AUTH_TYPE)) {
                try {
                    RequestContext requestContext = new RequestContext.Builder().build();
                    ResourceState state = connector.read(requestContext, "/auth/token-info/" + split[1]);

                    String realm = (String) state.getProperty("realm");
                    String subject = (String) state.getProperty("subject");

                    Set<String> roles = new HashSet<>();
                    Collection<? extends String> col = (Collection<? extends String>) state.getProperty("roles");
                    if (col != null) {
                        roles.addAll(col);
                    }

                    long issuedAt = ((Date) state.getProperty("issued-at")).getTime();

                    DefaultSecurityContext sc = (DefaultSecurityContext) req.requestContext().getSecurityContext();
                    sc.init(realm, subject, Collections.unmodifiableSet(roles), issuedAt);
                } catch (Throwable t) {
                    sendError(ctx, req, ResourceErrorResponse.ErrorType.NOT_AUTHORIZED);
                    return;
                }
            }
        }
        ctx.fireChannelRead(req);
    }

    private Set<String> getSet(ResourceState state, String name) {
        Set<String> set = new HashSet<>();
        Collection<? extends String> col = (Collection<? extends String>) state.getProperty(name);
        if (col != null) {
            set.addAll(col);
        }
        return Collections.unmodifiableSet(set);
    }

    private void sendError(ChannelHandlerContext ctx, ResourceRequest req, ResourceErrorResponse.ErrorType errorType) {
        ctx.writeAndFlush(new ResourceErrorResponse(req, errorType));
    }

}
