package io.liveoak.security.integration;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.liveoak.container.DefaultContainer;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.spi.AuthzPersister;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.security.spi.AuthzService;
import io.liveoak.security.spi.AuthzServiceConfig;
import io.liveoak.spi.InitializationException;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourceContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;
import io.liveoak.spi.resource.async.ResourceSink;
import io.liveoak.spi.resource.async.Responder;

/**
 * Root resource to be registered in DefaultContainer
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzServiceRootResource implements RootResource {

    private static final SimpleLogger log = new SimpleLogger(AuthzServiceRootResource.class);

    private String id;
    private DefaultContainer container;
    private AuthzService authzService;
    private AuthzPersister authzPersister;

    private final Map<String, Resource> childResources = new HashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();


    public AuthzServiceRootResource() {
    }

    public AuthzServiceRootResource(String id) {
        this.id = id;
    }

    @Override
    public void initialize(ResourceContext context) throws InitializationException {
        if (this.id == null) {
            this.id = context.config().get("id", null);
            if (this.id == null) {
                throw new InitializationException("no id specified");
            }
        }

        this.container = (DefaultContainer)context.container();

        String authzServiceClassName = context.config().get("service-class-name", "io.liveoak.security.impl.PolicyBasedAuthzService");
        String persisterClassName = context.config().get("persister-class-name", "io.liveoak.security.impl.InMemoryAuthzPersister");
        this.authzService = instantiateService(context, authzServiceClassName, AuthzService.class);
        this.authzPersister = instantiateService(context, persisterClassName, AuthzPersister.class);
        authzService.initialize(this);

        log.info("Services initialized. id=" + this.id + ", authzService=" + this.authzService + ", authzPersister=" + this.authzPersister);

        String authorizationConfig = context.config().get("authz-config", null);
        if (authorizationConfig != null) {
            AuthzServiceConfig authzServiceConfig = readPolicyConfiguration(context, authorizationConfig);
            log.info("Read policies config: " + authzServiceConfig);

            for (AuthzPolicyEntry configEntry : authzServiceConfig.getPolicies()) {
                authzPersister.registerAuthzPolicy(configEntry);
            }
        } else {
            log.info("Authorization config is null. Will use the default one");
            // TODO:
        }

        registerChildrenResources();
    }

    protected <T> T instantiateService(ResourceContext context, String className, Class<T> expectedClass) throws InitializationException {

        Class<?> serviceClass = null;
        try {
            serviceClass = Class.forName(className);
        } catch (ClassNotFoundException cnfe) {
            throw new InitializationException("Unable to load class " + className, cnfe);
        }

        if (!expectedClass.isAssignableFrom(serviceClass)) {
            throw new InitializationException("Class '" + serviceClass + "' not an instance of '" + expectedClass + "'");
        }

        try {
            return expectedClass.cast(serviceClass.newInstance());
        } catch (Exception e) {
            throw new InitializationException("Unable to instantiate implementation of class " + serviceClass, e);
        }
    }

    protected AuthzServiceConfig readPolicyConfiguration(ResourceContext context, String fileLocation) throws InitializationException {
        File configFile = new File(fileLocation);
        if (!configFile.exists()) {
            throw new InitializationException("AuthzService config file on location: " + fileLocation + " doesn't exists");
        }

        try {
            return objectMapper.readValue(configFile, AuthzServiceConfig.class);
        } catch (IOException ioe) {
            throw new InitializationException("Exception during parsing file: " + configFile, ioe);
        }
    }

    protected void registerChildrenResources() {
        this.childResources.put(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, new AuthzCheckResource(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, this));
    }

    @Override
    public void destroy() {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public String id() {
        return id;
    }

    public AuthzPersister getAuthzPersister() {
        return authzPersister;
    }

    public AuthzService getAuthzService() {
        return authzService;
    }

    public DefaultContainer getContainer() {
        return container;
    }

    protected Map<String, Resource> getChildResources() {
        return childResources;
    }

    @Override
    public void readMember(RequestContext ctx, String id, Responder responder) {
        try {
            if (!this.childResources.containsKey(id)) {
                responder.noSuchResource(id);
                return;
            }

            responder.resourceRead(this.childResources.get(id));

        } catch (Throwable t) {
            responder.internalError(t.getMessage());
        }
    }

    @Override
    public void readMembers(RequestContext ctx, ResourceSink sink) {
        this.childResources.values().forEach((e) -> {
            sink.accept(e);
        });

        sink.close();
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        // TODO: should be improved and probably handled with child resource
        Collection<AuthzPolicyEntry> policyEntries = this.authzPersister.getRegisteredAuthzPolicies();

        sink.accept("policies", policyEntries.toString());
        sink.close();
    }
}
