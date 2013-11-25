/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container;

import io.liveoak.container.codec.MediaTypeMatcher;
import io.liveoak.spi.resource.async.Resource;
import io.undertow.util.AttachmentKey;

/**
 * @author Bob McWhirter
 */
public class ResourceResponse {


    public static final AttachmentKey<ResourceResponse> ATTACHMENT_KEY = AttachmentKey.create( ResourceResponse.class );

    public enum ResponseType {
        CREATED,
        READ,
        UPDATED,
        DELETED,
        ERROR,
    }

    public ResourceResponse(ResourceRequest inReplyTo, ResponseType responseType) {
        this.inReplyTo = inReplyTo;
        this.responseType = responseType;
    }

    public ResourceResponse(ResourceRequest inReplyTo, ResponseType responseType, Resource resource) {
        this.inReplyTo = inReplyTo;
        this.responseType = responseType;
        this.resource = resource;
    }

    public MediaTypeMatcher mediaTypeMatcher() {
        return this.inReplyTo.mediaTypeMatcher();
    }

    public ResourceRequest inReplyTo() {
        return this.inReplyTo;
    }

    public ResponseType responseType() {
        return this.responseType;
    }

    public Resource resource() {
        return this.resource;
    }

    public String toString() {
        return "[ResourceResponse: type=" + this.responseType + "; object=" + this.resource + "]";
    }

    private ResourceRequest inReplyTo;
    private ResponseType responseType;
    private Resource resource;
}
