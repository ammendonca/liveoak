/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */

package io.liveoak.security.policy.uri.integration;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.policy.uri.complex.URIPolicy;
import io.liveoak.security.policy.uri.complex.URIPolicyRule;
import io.liveoak.security.spi.AuthzDecision;
import io.liveoak.spi.InitializationException;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourceContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;
import io.liveoak.spi.resource.async.ResourceSink;
import io.liveoak.spi.resource.async.Responder;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class URIPolicyRootResource implements RootResource {

    private static final SimpleLogger log = new SimpleLogger(URIPolicyRootResource.class);

    private String id;
    private URIPolicy uriPolicy;
    private URIPolicyConfig uriPolicyConfig;

    private final Map<String, Resource> childResources = new HashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();


    public URIPolicyRootResource() {
    }

    public URIPolicyRootResource(String id) {
        this.id = id;
    }

    @Override
    public void initialize(ResourceContext context) throws InitializationException {
        String policyConfig = context.config().get("policy-config", null);
        if (policyConfig != null) {
            this.uriPolicyConfig = readPolicyConfiguration(context, policyConfig);
        } else {
            log.info("Policy config is null. Will use the default one");
            this.uriPolicyConfig = createDefaultConfig();
        }

        log.info("URIPolicy config: " + uriPolicyConfig);

        createPolicy();
        registerChildrenResources();
    }

    protected URIPolicyConfig readPolicyConfiguration(ResourceContext context, String fileLocation) throws InitializationException {
        File configFile = new File(fileLocation);
        if (!configFile.exists()) {
            log.info("URIPolicyConfig file on location: " + fileLocation + " doesn't exists. Will use default config");
            return createDefaultConfig();
        } else {
            try {
                return objectMapper.readValue(configFile, URIPolicyConfig.class);
            } catch (IOException ioe) {
                throw new InitializationException("Exception during parsing file: " + configFile, ioe);
            }
        }
    }

    // Accept everything by default
    protected URIPolicyConfig createDefaultConfig() {
        URIPolicyConfig config = new URIPolicyConfig();
        config.setDefaultDecision(AuthzDecision.ACCEPT.toString());
        config.setUriRules(Collections.EMPTY_LIST);
        return config;
    }

    protected void createPolicy() {
        this.uriPolicy = new URIPolicy((policy) -> {

                for (URIPolicyConfigRule cfgRule : this.uriPolicyConfig.getUriRules()) {
                    URIPolicyRule internalRule = URIPolicyRule.createRule(cfgRule.getPriority(), cfgRule.getUriPattern(),
                            cfgRule.getQueryParamsCondition(), cfgRule.getRequestType(), cfgRule.getAllowedRoles(), cfgRule.getDeniedRoles(),
                            cfgRule.getAllowedUsers(), cfgRule.getDeniedUsers());
                    policy.addURIPolicyRule(internalRule);
                }

        });

        this.uriPolicy.initialize();
    }


    protected void registerChildrenResources() {
        this.childResources.put(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, new URIPolicyCheckResource(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, this));
    }

    @Override
    public void destroy() {
        // Nothing here for now
    }

    @Override
    public String id() {
        return id;
    }

    public URIPolicy getUriPolicy() {
        return uriPolicy;
    }

    public URIPolicyConfig getUriPolicyConfig() {
        return uriPolicyConfig;
    }

    @Override
    public void readMember(RequestContext ctx, String id, Responder responder) {
        try {
            if (!this.childResources.containsKey(id)) {
                responder.noSuchResource(id);
                return;
            }

            responder.resourceRead(this.childResources.get(id));

        } catch (Throwable t) {
            responder.internalError(t.getMessage());
        }
    }

    @Override
    public void readMembers(RequestContext ctx, ResourceSink sink) {
        this.childResources.values().forEach((e) -> {
            sink.accept(e);
        });

        sink.close();
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        sink.accept("uriPolicyConfig", uriPolicyConfig.toString());
        sink.close();
    }
}
