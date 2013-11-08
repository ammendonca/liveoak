package io.liveoak.keycloak;

import io.liveoak.container.SimpleConfig;
import io.liveoak.spi.Config;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.state.ResourceState;
import io.liveoak.testtools.AbstractResourceTestCase;
import org.jboss.resteasy.jose.jws.JWSBuilder;
import org.jboss.resteasy.jwt.JsonSerialization;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelProvider;
import org.keycloak.representations.SkeletonKeyToken;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class KeycloakRootResourceTest extends AbstractResourceTestCase {

    private KeycloakRootResource keycloak;
    private PrivateKey privateKey;

    @Before
    public void before() throws Exception {
        KeycloakSession session = keycloak.createSession();
        try {
            privateKey = session.getRealm(keycloak.getRealm()).getPrivateKey();
        } finally {
            session.close();
        }
    }

    @Override
    public RootResource createRootResource() {
        keycloak = new KeycloakRootResource("auth");
        return keycloak;
    }

    @Test
    public void testTokenInfo() throws Exception {
        RequestContext requestContext = new RequestContext.Builder().build();

        SkeletonKeyToken token = createToken();

        ResourceState returnedState = connector.read(requestContext, "/auth/token-info/" + toString(token));

        assertEquals(keycloak.getRealm(), returnedState.getProperty("realm"));
        assertEquals("user-id", returnedState.getProperty("subject"));
        assertEquals(token.getIssuedAt(), ((Date) returnedState.getProperty("issued-at")).getTime());

        List<String> roles = (List<String>) returnedState.getProperty("roles");
        assertEquals(3, roles.size());
        assertTrue(roles.contains("realm-role"));
        assertTrue(roles.contains("app-id/app-role"));
        assertTrue(roles.contains("app2-id/app-role"));
    }

    private SkeletonKeyToken createToken() {
        SkeletonKeyToken token = new SkeletonKeyToken();
        token.id("token-id");
        token.principal("user-id");
        token.audience(keycloak.getRealm());
        token.expiration(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(300));
        token.issuedFor("app-id");
        token.issuedNow();

        token.setRealmAccess(new SkeletonKeyToken.Access().roles(Collections.singleton("realm-role")));
        token.addAccess("app-id").roles(Collections.singleton("app-role"));
        token.addAccess("app2-id").roles(Collections.singleton("app-role"));

        return token;
    }

    private String toString(SkeletonKeyToken token) throws Exception {
        byte[] tokenBytes = JsonSerialization.toByteArray(token, false);
        return new JWSBuilder().content(tokenBytes).rsa256(privateKey);
    }

}
