package org.projectodd.restafari.vertx;

import org.junit.Test;
import org.projectodd.restafari.spi.resource.Resource;
import org.projectodd.restafari.spi.resource.RootResource;
import org.projectodd.restafari.spi.resource.async.PropertyResource;
import org.projectodd.restafari.testtools.AbstractResourceTestCase;
import org.projectodd.restafari.vertx.adapter.CollectionResourceAdapter;
import org.projectodd.restafari.vertx.adapter.ResponseBuilder;
import org.projectodd.restafari.vertx.resource.RootVertxCollectionResource;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;

import java.util.HashMap;
import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;

/**
 * @author Bob McWhirter
 */
public class VertxResourceTest extends AbstractResourceTestCase {

    @Override
    public RootResource createRootResource() {
        return new RootVertxCollectionResource("vertx", "test.vertx");
    }

    @Test
    public void testGenerally() throws Exception {

        CollectionResourceAdapter adapter = new CollectionResourceAdapter(vertx, "test.vertx");

        Map<String, JsonObject> objects = new HashMap<>();

        JsonObject bob = new JsonObject().putString("id", "bob").putString("name", "Bob McWhirter");
        objects.put("bob", bob);
        JsonObject ben = new JsonObject().putString("id", "ben").putString("name", "Ben Browning");
        objects.put("ben", ben);

        adapter.readMemberHandler( (id, responder) -> {
            System.err.println( "**** READ: " + id + " , " + responder );
            JsonObject object = objects.get(id);

            if (object != null) {
                responder.resourceRead( object );
            } else {
                responder.noSuchResource( id );
            }
        });

        adapter.readMembersHandler((responder) -> {
            JsonArray resources = new JsonArray( objects.values().toArray() );
            responder.resourcesRead( resources );
        });

        adapter.start();

        Resource result = connector.read("/vertx/bob");
        System.err.println("result: " + result);
        assertThat(result).isNotNull();

        result = connector.read("/vertx/bob/name");

        assertThat(result).isInstanceOf(PropertyResource.class);

        assertThat(((PropertyResource) result).get(null)).isEqualTo("Bob McWhirter");


    }
}
