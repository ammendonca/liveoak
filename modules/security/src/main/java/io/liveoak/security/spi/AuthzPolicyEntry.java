/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;


import io.liveoak.spi.ResourcePath;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzPolicyEntry {

    private final String id;
    private final Set<ResourcePath> includedResourcePrefixes = new HashSet<>();
    private final Set<ResourcePath> excludedResourcePrefixes = new HashSet<>();
    private final AuthzPolicy authzPolicy;

    public AuthzPolicyEntry(String id, AuthzPolicy authzPolicy) {
        this.id = id;
        this.authzPolicy = authzPolicy;
    }

    public String getId() {
        return id;
    }

    public AuthzPolicy getAuthzPolicy() {
        return authzPolicy;
    }

    public Set<ResourcePath> getIncludedResourcePrefixes() {
        return Collections.unmodifiableSet(includedResourcePrefixes);
    }

    public Set<ResourcePath> getExcludedResourcePrefixes() {
        return Collections.unmodifiableSet(excludedResourcePrefixes);
    }

    public AuthzPolicyEntry addIncludedResourcePrefix(ResourcePath path) {
        includedResourcePrefixes.add(path);
        return this;
    }

    public AuthzPolicyEntry addIncludedResourcePrefix(String uriPrefix) {
        includedResourcePrefixes.add(new ResourcePath(uriPrefix));
        return this;
    }

    public AuthzPolicyEntry addExcludedResourcePrefix(ResourcePath path) {
        excludedResourcePrefixes.add(path);
        return this;
    }

    public AuthzPolicyEntry addExcludedResourcePrefix(String uriPrefix) {
        excludedResourcePrefixes.add(new ResourcePath(uriPrefix));
        return this;
    }

    public boolean removeIncludedResourcePrefix(ResourcePath path) {
        return includedResourcePrefixes.remove(path);
    }

    public boolean removeIncludedResourcePrefix(String uriPrefix) {
        return includedResourcePrefixes.remove(new ResourcePath(uriPrefix));
    }

    public boolean removeExcludedResourcePrefix(ResourcePath path) {
        return excludedResourcePrefixes.remove(path);
    }

    public boolean removeExcludedResourcePrefix(String uriPrefix) {
        return excludedResourcePrefixes.remove(new ResourcePath(uriPrefix));
    }

    @Override
    public String toString() {
        return new StringBuilder("AuthzPolicyEntry [ ")
                .append("id=").append(id)
                .append(", includedResourcePrefixes=").append(includedResourcePrefixes)
                .append(", excludedResourcePrefixes=").append(excludedResourcePrefixes)
                .append(", authzPolicy=").append(authzPolicy)
                .append(" ]").toString();
    }


    /**
     * Check if resourcePath is subject of this policy according to includedResourcePrefixes and excludedResourcePrefixes
     *
     * @param resourcePath
     * @return true if resource is subject of this policy
     */
    public boolean isResourceMapped(ResourcePath resourcePath) {
        String resPathString = resourcePath.toString();

        // Check excluded first
        for (ResourcePath current : excludedResourcePrefixes) {
            if (resPathString.startsWith(current.toString())) {
                return false;
            }
        }

        for (ResourcePath current : includedResourcePrefixes) {
            if (resPathString.startsWith(current.toString())) {
                return true;
            }
        }

        return false;
    }
}
