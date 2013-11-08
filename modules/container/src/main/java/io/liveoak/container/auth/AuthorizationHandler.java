/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.auth;

import io.liveoak.container.ResourceErrorResponse;
import io.liveoak.container.ResourceRequest;
import io.liveoak.security.impl.AuthConstants;
import io.liveoak.security.impl.AuthServicesHolder;
import io.liveoak.security.impl.DefaultAuthToken;
import io.liveoak.security.impl.SimpleLogger;
import io.liveoak.security.spi.AuthToken;
import io.liveoak.security.spi.AuthorizationRequestContext;
import io.liveoak.security.spi.AuthorizationService;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.SecurityContext;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Handler for checking authorization of current request. It's independent of protocol. It delegates the work to {@link AuthorizationService}.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthorizationHandler extends SimpleChannelInboundHandler<ResourceRequest> {

    // TODO: replace with real logging
    private static final SimpleLogger log = new SimpleLogger(AuthorizationHandler.class);

    // TODO: Should be removed...
    static {
        try {
            AuthServicesHolder.getInstance().registerClassloader(AuthorizationHandler.class.getClassLoader());
            AuthServicesHolder.getInstance().registerDefaultPolicies();
        } catch (Throwable e) {
            log.error("Error occured during initialization of AuthorizationService", e);
            throw e;
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ResourceRequest req) throws Exception {
        try {
            // TODO Creating AuthToken here is temporary
            AuthToken token = createAuthToken(req.requestContext().getSecurityContext());

            AuthorizationService authService = AuthServicesHolder.getInstance().getAuthorizationService();
            RequestContext reqContext = req.requestContext();

            if (authService.isAuthorized(new AuthorizationRequestContext(token, reqContext))) {
                ctx.fireChannelRead(req);
            } else {
                sendAuthorizationError(ctx, req);
            }
        } catch (Throwable e) {
            log.error("Exception occured in AuthorizationService check", e);
            throw e;
        }
    }

    private AuthToken createAuthToken(SecurityContext sc) {
        if (sc.isAuthenticated()) {
            Set<String> realmRoles = new HashSet<>();
            Map<String, Set<String>> appRoles = new HashMap<>();

            for (String role : sc.getRoles()) {
                int i = role.indexOf('/');
                if (i == -1) {
                    realmRoles.add(role);
                } else {
                    String a = role.substring(0, i);
                    String r = role.substring(i + 1);
                    if (!appRoles.containsKey(a)) {
                        appRoles.put(a, new HashSet<>());
                    }
                    appRoles.get(a).add(r);
                }
            }

            return new DefaultAuthToken(sc.getSubject(), sc.getRealm(), "app", -1, -1, sc.lastVerified(), null, realmRoles, appRoles);
        } else {
            return new DefaultAuthToken(null, null, null, -1, -1, 01, null, Collections.emptySet(), Collections.emptyMap());
        }
    }

    protected void sendAuthorizationError(ChannelHandlerContext ctx, ResourceRequest req) {
        ctx.writeAndFlush(new ResourceErrorResponse(req, ResourceErrorResponse.ErrorType.NOT_AUTHORIZED));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        super.exceptionCaught(ctx, cause);
    }
}
