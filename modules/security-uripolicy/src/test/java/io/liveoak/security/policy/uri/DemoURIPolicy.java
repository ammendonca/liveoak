/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.policy.uri;

import io.liveoak.security.policy.uri.complex.URIPolicy;
import io.liveoak.security.policy.uri.complex.URIPolicyRule;

/**
 * Demo policy with pre-configured rules for testing purposes
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DemoURIPolicy extends URIPolicy {

    @Override
    protected void doInit() {
        super.doInit();

        // Rule specifies that READ requests to '/droolsTest/foo' are accepted for members of realm roles "role1" and "role2"
        URIPolicyRule rule1 = URIPolicyRule.createEntry(8, "/droolsTest/foo", null,
                "READ", "\"role1\", \"role2\"", null, null, null);

        // Rule specifies that requests to '/droolsTest/*' are accepted if params condition matched as well
        URIPolicyRule rule2 = URIPolicyRule.createEntry(9, "/droolsTest/*", "resourceParams.value(\"param1\") == \"foo\" && resourceParams.intValue(\"param2\") >= 10",
                "*", null, null, "\"*\"", null);

        // Rule specifies that requests, which permits everything if URI matches regex and all params condition matched as well
        URIPolicyRule rule3 = URIPolicyRule.createEntry(9, "/droolsTest/*/bar/([abc].*)", "resourceParams.value(\"param1\") == $uriMatcher.group(1) && resourceParams.value(\"param2\") == $uriMatcher.group(2) && resourceParams.value(\"param3\") == $securityContext.subject",
                "*", null, null, "\"*\"", null);


        // Rule specifies that URI like '/droolsTest/foo' is available for user with username 'foo' (Last part must be username of current user)
        URIPolicyRule rule4 = URIPolicyRule.createEntry(10, "/droolsTest/{ $securityContext.subject }", null,
                "*", null, null, "$securityContext.subject", null);

        // Rule specifies that URI like '/droolsTest/foo' is available for user, which has realmRole 'foo' (Last part must be some realmRole of current user)
        URIPolicyRule rule5 = URIPolicyRule.createEntry(10, "/droolsTest/{ any($securityContext.roles) }", null,
                "*", null, null, "\"*\"", null);

        // Rule specifies that all requests to '/droolsTest/foo' are accepted for members of realm roles "role3" (similar to rule1, but this is for all requests)
        // NOTE: Read requests to /droolsTest/foo will be preferably processed by rule1 because it has bigger priority
        URIPolicyRule rule6 = URIPolicyRule.createEntry(5, "/droolsTest/foo", null,
                "*", null, "\"role1\"", "\"*\"", null);


        // Killer rule with big priority. Automatically denies all requests if user is member of realm role "evilRole"
        URIPolicyRule rule7 = URIPolicyRule.createEntry(20, "/droolsTest/*", null,
                "*", null, "\"evilRole\"", null, null);

        this.addURIPolicyEntry(rule1);
        this.addURIPolicyEntry(rule2);
        this.addURIPolicyEntry(rule3);
        this.addURIPolicyEntry(rule4);
        this.addURIPolicyEntry(rule5);
        this.addURIPolicyEntry(rule6);
        this.addURIPolicyEntry(rule7);
    }
}
