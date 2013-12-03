/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;

import java.util.Collection;

/**
 * Component responsible for save/load of all policies and security related data
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface AuthzPersister {

    /**
     * Will either add new policy or edit existing policy for given application
     *
     * @param policyEntry policyEntry to add or update
     */
    void registerAuthzPolicy(AuthzPolicyEntry policyEntry);

    /**
     * Return list of registered Authorization policies for given application
     *
     * @return all Authorization policies or empty list if no policies are registered for this application
     */
    Collection<AuthzPolicyEntry> getRegisteredAuthzPolicies();


    /**
     * Return registered policy
     *
     * @param policyName
     * @return Return registered policy by name or null if policy with this name doesn't exists
     */
    AuthzPolicyEntry getAuthzPolicyByName(String policyName);
}
