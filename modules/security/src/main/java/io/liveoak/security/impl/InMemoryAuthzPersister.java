/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.security.spi.AuthzPersister;
import io.liveoak.security.spi.AuthzPolicyEntry;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InMemoryAuthzPersister implements AuthzPersister {

    private Map<String, AuthzPolicyEntry> authzPolicies = new ConcurrentHashMap<>();

    @Override
    public Collection<AuthzPolicyEntry> getRegisteredAuthzPolicies() {
        return authzPolicies == null ? Collections.EMPTY_SET : Collections.unmodifiableCollection(authzPolicies.values());
    }

    @Override
    public void registerAuthzPolicy(AuthzPolicyEntry policyEntry) {
        authzPolicies.put(policyEntry.getPolicyName(), policyEntry);
    }

    @Override
    public AuthzPolicyEntry getAuthzPolicyByName(String policyName) {
        return authzPolicies.get(policyName);
    }
}
