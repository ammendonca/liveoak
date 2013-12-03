/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;

import io.liveoak.security.integration.AuthzServiceRootResource;
import io.liveoak.spi.RequestContext;

/**
 * Service providing authorization
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface AuthzService {

    /**
     * initialize service
     *
     * @param rootResource
     */
    void initialize(AuthzServiceRootResource rootResource);

    /**
     * Decide if request is authorized or not. Assumption is that request has been already authenticated and securityContext is
     * already established
     *
     * @param requestContext encapsulates all info about current request.
     * @return true if request is authorized
     */
    boolean isAuthorized(RequestContext requestContext);
}
