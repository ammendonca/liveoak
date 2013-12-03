/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.container.DefaultRequestAttributes;
import io.liveoak.container.DirectConnector;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.integration.AuthzServiceRootResource;
import io.liveoak.security.spi.AuthzDecision;
import io.liveoak.security.spi.AuthzPersister;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.security.spi.AuthzService;
import io.liveoak.spi.RequestAttributes;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourcePath;
import io.liveoak.spi.state.ResourceState;

import java.util.Collection;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PolicyBasedAuthzService implements AuthzService {

    private static final SimpleLogger log = new SimpleLogger(PolicyBasedAuthzService.class);

    private AuthzPersister authzPersister;
    private DirectConnector directConnector;

    @Override
    public void initialize(AuthzServiceRootResource authzServiceRootResource) {
        this.authzPersister = authzServiceRootResource.getAuthzPersister();
        this.directConnector = authzServiceRootResource.getContainer().directConnector();
    }


    @Override
    public boolean isAuthorized(RequestContext reqContext) {
        boolean someSuccess = false;

        // Find all policies for particular application
        Collection<AuthzPolicyEntry> policies = this.authzPersister.getRegisteredAuthzPolicies();

        if (policies.size() == 0) {
            throw new IllegalStateException("No policies configured");
        }

        for (AuthzPolicyEntry policyEntry : policies) {
            ResourcePath resPath = reqContext.resourcePath();

            // Check if policy is mapped to actual resourcePath
            if (policyEntry.isResourceMapped(resPath)) {
                String policyEndpoint = policyEntry.getPolicyResourceEndpoint();

                if (log.isTraceEnabled()) {
                    log.trace("Going to trigger policyName " + policyEntry.getPolicyName() + " for request: " + reqContext);
                }

                // TODO: This should be triggered concurrently with usage of future objects
                AuthzDecision decision = invokePolicyEndpoint(reqContext, policyEndpoint);
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

    protected AuthzDecision invokePolicyEndpoint(RequestContext reqContext, String policyEndpoint) {
        // Put current request as attribute of the authzRequest
        RequestAttributes attribs = new DefaultRequestAttributes();
        attribs.setAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, reqContext);
        RequestContext authzRequest = new RequestContext.Builder().requestAttributes(attribs).build();

        try {
            ResourceState resourceState = this.directConnector.read(authzRequest, policyEndpoint);
            Object result = resourceState.getProperty(AuthzConstants.ATTR_AUTHZ_POLICY_RESULT);
            return (AuthzDecision)result;
        } catch (InterruptedException ie) {
            log.error("Interrupted", ie);
            Thread.currentThread().interrupt();
            return AuthzDecision.REJECT;
        } catch (Exception e) {
            log.error("Couldn't invoke policyEndpoint " + policyEndpoint + " due to exception", e);
            return AuthzDecision.REJECT;
        }
    }
}
