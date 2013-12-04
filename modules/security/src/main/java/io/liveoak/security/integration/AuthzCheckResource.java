/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */

package io.liveoak.security.integration;

import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.spi.AuthzService;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzCheckResource implements Resource {

    private static final SimpleLogger log = new SimpleLogger(AuthzCheckResource.class);

    private final String id;
    private final AuthzServiceRootResource parent;

    public AuthzCheckResource(String id, AuthzServiceRootResource parent) {
        this.id = id;
        this.parent = parent;
    }

    @Override
    public Resource parent() {
        return parent;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        AuthzService authzService = parent.getAuthzService();

        RequestContext reqCtxToAuthorize = ctx.requestAttributes()!= null ? ctx.requestAttributes().getAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, RequestContext.class) : null;
        if (reqCtxToAuthorize == null) {
            log.warn("requestContext to authorize is null!");
            sink.accept("error", "requestContext is null");
        } else {
            boolean result = authzService.isAuthorized(reqCtxToAuthorize);
            sink.accept(AuthzConstants.ATTR_AUTHZ_RESULT, result);
        }
        sink.close();
    }
}
