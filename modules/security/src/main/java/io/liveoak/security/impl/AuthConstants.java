/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

/**
 * TODO: Probably remove and init everything from JSON or something...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthConstants {

    // Default applicationId. Metadata and default policy are actually registered for application with this ID
    public static final String DEFAULT_APP_ID = "DEFAULT_APP_ID";

    // Name of realm and application and publicKey, which will be registered by default under DEFAULT_APP_ID
    public static final String DEFAULT_REALM_NAME = "realmName1";
    public static final String DEFAULT_APPLICATION_NAME = "appName1";

}
