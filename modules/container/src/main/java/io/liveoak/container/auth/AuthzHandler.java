/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.auth;

import io.liveoak.container.DefaultRequestAttributes;
import io.liveoak.container.DirectConnector;
import io.liveoak.container.ResourceErrorResponse;
import io.liveoak.container.ResourceRequest;
import io.liveoak.spi.RequestAttributes;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.state.ResourceState;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;


/**
 * Handler for checking authorization of current request. It's independent of protocol.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzHandler extends SimpleChannelInboundHandler<ResourceRequest> {

    // TODO: replace with real logging
    private static final SimpleLogger log = new SimpleLogger(AuthzHandler.class);

    private final DirectConnector connector;

    public AuthzHandler(DirectConnector connector) {
        this.connector = connector;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ResourceRequest req) throws Exception {
        try {
            // Put current request as attribute of the request, which will be sent to AuthzService
            RequestAttributes attribs = new DefaultRequestAttributes();
            attribs.setAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, req.requestContext());
            RequestContext authzRequest = new RequestContext.Builder().requestAttributes(attribs).build();

            ResourceState resourceState = this.connector.read(authzRequest, "/authz/authzCheck");
            Boolean result = (Boolean)resourceState.getProperty(AuthzConstants.ATTR_AUTHZ_RESULT);

            if (result) {
                ctx.fireChannelRead(req);
            } else {
                sendError(ctx, req);
            }
        } catch (Throwable e) {
            log.error("Exception catched in AuthzHandler", e);
            sendError(ctx, req);
        }
    }

    protected void sendError(ChannelHandlerContext ctx, ResourceRequest req) {
        // Send 403 if request is authenticated or 401 if it is not
        boolean isAuthenticated = req.requestContext().securityContext().isAuthenticated();
        ResourceErrorResponse.ErrorType errorType = isAuthenticated ? ResourceErrorResponse.ErrorType.FORBIDDEN : ResourceErrorResponse.ErrorType.NOT_AUTHORIZED;

        ctx.writeAndFlush(new ResourceErrorResponse(req, errorType));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        super.exceptionCaught(ctx, cause);
    }
}
