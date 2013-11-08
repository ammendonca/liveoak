/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.spi;

import java.security.PublicKey;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ApplicationMetadata {

    // MBAAS configuration
    private final String applicationId;

    // Parameters from Keycloak
    private final String realmName;
    private final String applicationName;

    public ApplicationMetadata(String applicationId, String realmName, String applicationName) {
        this.applicationId = applicationId;
        this.realmName = realmName;
        this.applicationName = applicationName;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getApplicationName() {
        return applicationName;
    }
}
