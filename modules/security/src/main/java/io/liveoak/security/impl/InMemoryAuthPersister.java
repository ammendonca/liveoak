/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.security.spi.AppMetadata;
import io.liveoak.security.spi.AuthPersister;
import io.liveoak.security.spi.AuthzPolicyEntry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InMemoryAuthPersister implements AuthPersister {

    // TODO: Thread-safety
    private Map<String, AppMetadata> applicationMetadataMap = new HashMap<>();
    private Map<String, List<AuthzPolicyEntry>> authPolicies = new HashMap<>();

    @Override
    public void registerApplicationMetadata(AppMetadata appMetadata) {
        applicationMetadataMap.put(appMetadata.getApplicationId(), appMetadata);
    }

    @Override
    public AppMetadata getApplicationMetadata(String applicationKey) {
        return applicationMetadataMap.get(applicationKey);
    }

    @Override
    public List<AuthzPolicyEntry> getRegisteredPolicies(String applicationKey) {
        List<AuthzPolicyEntry> policies = authPolicies.get(applicationKey);
        return policies == null ? Collections.EMPTY_LIST : Collections.unmodifiableList(policies);
    }

    @Override
    public void registerPolicy(String applicationKey, AuthzPolicyEntry policy) {
        List<AuthzPolicyEntry> policies = authPolicies.get(applicationKey);
        if (policies == null) {
            policies = new ArrayList<>();
            authPolicies.put(applicationKey, policies);
        }
        policies.add(policy);
    }
}
