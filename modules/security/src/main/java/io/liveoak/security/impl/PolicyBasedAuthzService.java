/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.security.spi.AuthzDecision;
import io.liveoak.security.spi.AuthzPolicy;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.security.spi.AuthzRequestContext;
import io.liveoak.security.spi.AuthzService;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourcePath;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PolicyBasedAuthzService implements AuthzService {

    SimpleLogger log = new SimpleLogger(PolicyBasedAuthzService.class);

    @Override
    public boolean isAuthorized(AuthzRequestContext authRequestContext) {
        boolean someSuccess = false;
        RequestContext request = authRequestContext.getRequestContext();

        // Find all policies for particular application
        String appId = AuthServicesHolder.getInstance().getApplicationIdResolver().resolveAppId(request);
        List<AuthzPolicyEntry> policies = AuthServicesHolder.getInstance().getAuthPersister().getRegisteredPolicies(appId);

        if (policies.size() == 0) {
            throw new IllegalStateException("No policies configured for application " + appId);
        }

        for (AuthzPolicyEntry policyEntry : policies) {
            ResourcePath resPath = request.resourcePath();

            // Check if policy is mapped to actual resourcePath
            if (policyEntry.isResourceMapped(resPath)) {
                AuthzPolicy policy = policyEntry.getAuthzPolicy();

                if (log.isTraceEnabled()) {
                    log.trace("Going to trigger policy for request: " + request + ", policyEntry: " + policyEntry);
                }
                AuthzDecision decision = policy.isAuthorized(authRequestContext);
                if (log.isTraceEnabled()) {
                    log.trace("Result of authorization policy check: " + decision);
                }

                if (decision == AuthzDecision.REJECT) {
                    // reject always wins
                    return false;
                } else if (decision == AuthzDecision.ACCEPT) {
                    someSuccess = true;
                }
            }
        }

        return someSuccess;
    }
}
