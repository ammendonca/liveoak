/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */

package io.liveoak.security.impl;

import io.liveoak.container.DefaultRequestAttributes;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.security.integration.AuthzServiceRootResource;
import io.liveoak.spi.RequestAttributes;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.RequestType;
import io.liveoak.spi.ResourceNotFoundException;
import io.liveoak.spi.ResourcePath;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.state.ResourceState;
import io.liveoak.testtools.AbstractResourceTestCase;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzServiceRootResourceTest extends AbstractResourceTestCase {

    @Override
    public RootResource createRootResource() {
        AuthzServiceRootResource resource = new AuthzServiceRootResource("authz");
        return resource;
    }

    @Test
    public void testAuthzServiceRequest() throws Exception {
        RequestContext reqCtx = new RequestContext.Builder().build();
        ResourceState state = connector.read(reqCtx, "/authz");
        String policiesProperty = (String)state.getProperty("policies");
        Assert.assertNotNull(policiesProperty);
        Assert.assertTrue(policiesProperty.contains("URIPolicy"));


        boolean authzCheckFound = false;
        for (ResourceState member : state.members()) {
            if (member.id().equals("authzCheck")) {
                authzCheckFound = true;
                break;
            }
        }
        Assert.assertTrue("Child resource 'authzCheck' not found", authzCheckFound);
    }

    @Test
    public void testAuthorizationRequest() throws Exception {
        // Send request without requestContext attachment. It should fail with "null error"
        RequestContext reqCtx = new RequestContext.Builder().build();
        ResourceState state = connector.read(reqCtx, "/authz/authzCheck");
        String error = (String)state.getProperty("error");
        Assert.assertNotNull("error");
        Assert.assertTrue(error.equals("requestContext is null"));

        // Send request with requestContext attachement. It will fail as uriPolicy resource is not available
        RequestContext reqCtxToCheck = new RequestContext.Builder().requestType(RequestType.READ).resourcePath(new ResourcePath("/storage/some"));
        RequestAttributes attribs = new DefaultRequestAttributes();
        attribs.setAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, reqCtxToCheck);
        reqCtx = new RequestContext.Builder().requestAttributes(attribs).build();
        ResourceState errorState = connector.read(reqCtx, "/authz/authzCheck");
        Assert.assertFalse((Boolean)errorState.getProperty(AuthzConstants.ATTR_AUTHZ_RESULT));
    }
}
