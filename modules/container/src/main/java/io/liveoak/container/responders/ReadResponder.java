/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.responders;

import io.liveoak.container.ResourceRequest;
import io.liveoak.container.ResourceResponseSink;
import io.liveoak.spi.resource.async.Resource;
import io.netty.channel.ChannelHandlerContext;
import io.undertow.server.HttpServerExchange;

import java.util.concurrent.Executor;

/**
 * @author Bob McWhirter
 */
public class ReadResponder extends TraversingResponder {

    public ReadResponder(Executor executor, Resource root, ResourceRequest inReplyTo, ResourceResponseSink sink) {
        super(executor, root, inReplyTo, sink );
    }

    @Override
    protected void perform(Resource resource) {
        createBaseResponder().resourceRead(resource);
    }

}
