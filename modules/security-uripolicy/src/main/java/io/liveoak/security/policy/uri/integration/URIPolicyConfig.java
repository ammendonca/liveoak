/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */

package io.liveoak.security.policy.uri.integration;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class URIPolicyConfig {

    private List<URIPolicyConfigRule> uriRules;
    private String defaultDecision;

    public List<URIPolicyConfigRule> getUriRules() {
        return uriRules;
    }

    public void setUriRules(List<URIPolicyConfigRule> uriRules) {
        this.uriRules = uriRules;
    }

    public String getDefaultDecision() {
        return defaultDecision;
    }

    public void setDefaultDecision(String defaultDecision) {
        this.defaultDecision = defaultDecision;
    }

    @Override
    public String toString() {
        return new StringBuilder("URIPolicyConfig [ ")
                .append("defaultDecision=").append(defaultDecision)
                .append(", uriRules=").append(uriRules)
                .append(" ]").toString();
    }
}
