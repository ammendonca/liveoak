/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;


import io.liveoak.spi.ResourcePath;

import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzPolicyEntry {

    private String policyName;
    private List<String> includedResourcePrefixes;
    private List<String> excludedResourcePrefixes;
    private String policyResourceEndpoint;

    public String getPolicyName() {
        return policyName;
    }

    public List<String> getIncludedResourcePrefixes() {
        return Collections.unmodifiableList(includedResourcePrefixes);
    }

    public List<String> getExcludedResourcePrefixes() {
        return Collections.unmodifiableList(excludedResourcePrefixes);
    }

    public String getPolicyResourceEndpoint() {
        return policyResourceEndpoint;
    }

    @Override
    public String toString() {
        return new StringBuilder("AuthzPolicyEntry [ ")
                .append("policyName=").append(policyName)
                .append(", includedResourcePrefixes=").append(includedResourcePrefixes)
                .append(", excludedResourcePrefixes=").append(excludedResourcePrefixes)
                .append(", policyResourceEndpoint=").append(policyResourceEndpoint)
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
        for (String current : excludedResourcePrefixes) {
            if (resPathString.startsWith(current)) {
                return false;
            }
        }

        for (String current : includedResourcePrefixes) {
            if (resPathString.startsWith(current.toString())) {
                return true;
            }
        }

        return false;
    }
}
