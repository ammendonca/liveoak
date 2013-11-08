package io.liveoak.container;

import io.liveoak.spi.SecurityContext;

import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultSecurityContext implements SecurityContext {

    private boolean initialized;
    private String realm;
    private String subject;
    private Set<String> roles;
    private long lastVerified;

    public DefaultSecurityContext() {
    }

    public void init(String realm, String subject, Set<String> roles, long lastVerified) {
        if (initialized) {
            throw new IllegalStateException("Already initialized");
        }
        initialized = true;

        this.realm = realm;
        this.subject = subject;
        this.roles = roles;
        this.lastVerified = lastVerified;
    }

    @Override
    public boolean isAuthenticated() {
        return realm != null && subject != null;
    }

    @Override
    public String getRealm() {
        return realm;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public long lastVerified() {
        return lastVerified;
    }

    @Override
    public Set<String> getRoles() {
        return roles;
    }

    @Override
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

}
