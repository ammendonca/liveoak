package io.liveoak.keycloak;

import io.liveoak.spi.InitializationException;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourceContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.resource.async.Responder;
import org.jboss.resteasy.jwt.JsonSerialization;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ApplicationRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.managers.ApplicationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.testutils.KeycloakServer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class KeycloakRootResource implements RootResource {

    private String id;
    private KeycloakServer server;
    private String realm;
    private PublicKey publicKey;

    public KeycloakRootResource() {
    }

    public KeycloakRootResource(String id) {
        this.id = id;
    }

    public String getRealm() {
        return realm;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public KeycloakSession createSession() {
        return server.getKeycloakSessionFactory().createSession();
    }

    @Override
    public void initialize(ResourceContext context) throws InitializationException {
        if (this.id == null) {
            this.id = context.config().get("id", null);
            if (this.id == null) {
                throw new InitializationException("no id specified");
            }
        }

        String appImport = context.config().get("import", null);
        realm = context.config().get("realm", "default");

        // TODO Container should set this
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

        server = new KeycloakServer();
        try {
            server.start();

            KeycloakSessionFactory factory = server.getKeycloakSessionFactory();
            KeycloakSession session = factory.createSession();
            session.getTransaction().begin();

            RealmManager realmManager = new RealmManager(session);
            ApplicationManager appManager = new ApplicationManager(realmManager);

            RealmModel realmModel = realmManager.getRealm(realm);
            if (realmModel == null) {
                RealmRepresentation realmRep = new RealmRepresentation();
                realmRep.setId(realm);
                realmRep.setRealm(realm);
                realmRep.setEnabled(true);

                realmRep.setAccessCodeLifespan(10);
                realmRep.setAccessCodeLifespanUserAction(600);
                realmRep.setTokenLifespan(600);
                realmRep.setCookieLoginAllowed(true);
                realmRep.setSslNotRequired(true);

                realmRep.setAccountManagement(true);
                realmRep.setRegistrationAllowed(true);
                realmRep.setResetPasswordAllowed(true);

                realmRep.setRequiredCredentials(Collections.singleton(CredentialRepresentation.PASSWORD));
                realmRep.setRequiredOAuthClientCredentials(Collections.singleton(CredentialRepresentation.PASSWORD));
                realmRep.setRequiredApplicationCredentials(Collections.singleton(CredentialRepresentation.PASSWORD));

                realmModel = realmManager.createRealm(realmRep.getId(), realmRep.getRealm());
                realmManager.importRealm(realmRep, realmModel);
            }

            if (appImport != null) {
                File file = new File(appImport);
                if (file.isFile()) {
                    ApplicationRepresentation appRep = loadJson(new FileInputStream(file), ApplicationRepresentation.class);
                    if (!realmModel.getApplicationNameMap().containsKey(appRep.getId())) {
                        appManager.createApplication(realmModel, appRep);
                    }
                }
            }

            session.getTransaction().commit();
            session.close();

            publicKey = realmModel.getPublicKey();
        } catch (Throwable t) {
            throw new InitializationException(t);
        }

        Thread.currentThread().setContextClassLoader(cl);
    }

    private static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            int c;
            while ((c = is.read()) != -1) {
                os.write(c);
            }
            byte[] bytes = os.toByteArray();
            return JsonSerialization.fromBytes(type, bytes);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

    @Override
    public void destroy() {
        server.stop();
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public void readMember(RequestContext ctx, String id, Responder responder) {
        switch (id) {
            case "token-info":
                responder.resourceRead(new TokenResource(this, id));
                return;
            default: responder.noSuchResource(id);
        }
    }

}

