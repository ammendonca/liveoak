/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.security.spi.AppMetadata;
import io.liveoak.security.spi.ApplicationIdResolver;
import io.liveoak.security.spi.AuthPersister;
import io.liveoak.security.spi.AuthzDecision;
import io.liveoak.security.spi.AuthzPolicy;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.security.spi.AuthzRequestContext;
import io.liveoak.security.spi.AuthzService;
import io.liveoak.spi.ResourcePath;

import java.util.HashSet;
import java.util.Set;


/**
 * Container for various services related to authentication/authorization
 * TODO: Probably remove later...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthServicesHolder {

    // TODO: replace with real logging
    private final SimpleLogger log = new SimpleLogger(AuthServicesHolder.class);

    private static AuthServicesHolder INSTANCE = new AuthServicesHolder();

    private final AuthzService authzService;
    private final AuthPersister authPersister;

    // TODO: Probably remove
    private ApplicationIdResolver applicationIdResolver;

    // TODO: Also remove... loading of policies should be done in mbaas way
    private final Set<ClassLoader> policyLoaders = new HashSet<>();

    private AuthServicesHolder() {
        this.authzService = new PolicyBasedAuthzService();
        this.authPersister = new InMemoryAuthPersister();
        this.applicationIdResolver = (resourceReq) -> AuthConstants.DEFAULT_APP_ID;

        // Register default loaders
        policyLoaders.add(AuthServicesHolder.class.getClassLoader());
        policyLoaders.add(Thread.currentThread().getContextClassLoader());

        // Register default metadata and URIPolicy for default application
        registerDefaultAppConfig();
    }

    ;

    public static AuthServicesHolder getInstance() {
        return INSTANCE;
    }

    public AuthzService getAuthzService() {
        return authzService;
    }

    public AuthPersister getAuthPersister() {
        return authPersister;
    }

    public ApplicationIdResolver getApplicationIdResolver() {
        return applicationIdResolver;
    }

    public void setApplicationIdResolver(ApplicationIdResolver applicationIdResolver) {
        this.applicationIdResolver = applicationIdResolver;
    }

    private void registerDefaultAppConfig() {
        AppMetadata appMetadata = new AppMetadata(AuthConstants.DEFAULT_APP_ID, AuthConstants.DEFAULT_REALM_NAME,
                AuthConstants.DEFAULT_APPLICATION_NAME);
        authPersister.registerApplicationMetadata(appMetadata);
    }

    public void registerClassloader(ClassLoader policyClassloader) {
        this.policyLoaders.add(policyClassloader);
    }

    public void registerDefaultPolicies() {
        // Register simple demo policy as default one
        AuthzPolicy simplePolicy = loadPolicy("io.liveoak.security.policy.uri.simple.DemoSimpleURIPolicy");
        simplePolicy.init();
        AuthzPolicyEntry simplePolicyEntry = new AuthzPolicyEntry("someId", simplePolicy);
        simplePolicyEntry.addIncludedResourcePrefix(new ResourcePath());
        // Don't test URI under /droolsTest/foo/bar/* with simple policy
        simplePolicyEntry.addExcludedResourcePrefix(new ResourcePath("/droolsTest/foo/bar"));

        // Register drools based URIPolicy for context /droolsTest
        AuthzPolicy droolsPolicy = loadPolicy("io.liveoak.security.policy.uri.complex.DemoURIPolicy");
        droolsPolicy.init();
        AuthzPolicyEntry droolsPolicyEntry = new AuthzPolicyEntry("someId2", droolsPolicy);
        droolsPolicyEntry.addIncludedResourcePrefix(new ResourcePath("droolsTest"));

        authPersister.registerPolicy(AuthConstants.DEFAULT_APP_ID, simplePolicyEntry);
        authPersister.registerPolicy(AuthConstants.DEFAULT_APP_ID, droolsPolicyEntry);

        AuthzPolicyEntry tmpStoragePolicy = new AuthzPolicyEntry("storage", new AuthzPolicy() {
            @Override
            public void init() {
            }

            @Override
            public AuthzDecision isAuthorized(AuthzRequestContext authRequestContext) {
                Set<String> roles = authRequestContext.getAuthToken().getApplicationRolesMap().get("test-app");
                return roles != null && roles.contains("storage") ? AuthzDecision.ACCEPT : AuthzDecision.REJECT;
            }
        });
        tmpStoragePolicy.addIncludedResourcePrefix(new ResourcePath("storage"));
        authPersister.registerPolicy(AuthConstants.DEFAULT_APP_ID, tmpStoragePolicy);
    }

    private AuthzPolicy loadPolicy(String policyClassname) {
        Class<?> clazz = null;
        for (ClassLoader cl : this.policyLoaders) {
            clazz = loadPolicyClass(policyClassname, cl);
            if (clazz != null) {
                break;
            }
        }

        if (clazz == null) {
            log.error("Unable to load policy class " + policyClassname);
            throw new IllegalStateException("Unable to load policy class: " + policyClassname + " with classloaders: " + policyLoaders);
        }

        try {
            return (AuthzPolicy) clazz.newInstance();
        } catch (Exception e) {
            log.error("Unable to instantiate instance of policy class " + clazz);
            throw new IllegalStateException("Unable to instantiate instance of policy class " + clazz);
        }
    }

    private static Class<?> loadPolicyClass(String policyClassname, ClassLoader cl) {
        try {
            return cl.loadClass(policyClassname);
        } catch (ClassNotFoundException cnfe) {
            return null;
        }
    }
}
