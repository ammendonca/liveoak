/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;

import java.util.List;

/**
 * Component responsible for save/load of all policies and security related data
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface AuthPersister {

    /**
     * Save/override applicationMetadata
     *
     * @param appMetadata to save
     */
    void registerApplicationMetadata(AppMetadata appMetadata);

    /**
     * Obtain applicationMetadata for given application
     *
     * @param applicationKey key/ID of application
     * @return loaded applicationMetadata or null if metadata not found for given key
     */
    AppMetadata getApplicationMetadata(String applicationKey);

    /**
     * Will either add new policy or edit existing policy for given application
     *
     * @param applicationKey key/ID of application
     * @param policy         policy to add or update
     */
    void registerPolicy(String applicationKey, AuthzPolicyEntry policy);

    /**
     * Return list of registered Authorization policies for given application
     *
     * @param applicationKey key/ID of application
     * @return all Authorization policies or empty list if no policies are registered for this application
     */
    List<AuthzPolicyEntry> getRegisteredPolicies(String applicationKey);
}
