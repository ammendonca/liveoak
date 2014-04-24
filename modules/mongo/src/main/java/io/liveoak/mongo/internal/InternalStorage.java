package io.liveoak.mongo.internal;

import com.mongodb.DBCollection;

/**
 * @author <a href="mailto:mwringe@redhat.com">Matt Wringe</a>
 */
public class InternalStorage {

    DBCollection collection;

    InternalStorage(DBCollection collection) {
        this.collection = collection;
    }

    /**
     * Returns a collection namespaced to a particular resource
     *
     * @return A collection for the resource to use
     */
    public DBCollection getCollection() {
        return this.collection;
    }

    /**
     * Returns a collection namespaced to the resource and appended with
     * the specified collectionName.
     *
     * Useful for when Resources need more than one collection.
     *
     * @param collectionName The name for a new collection
     * @return A collection for the resource to use
     */
    public DBCollection getCollection(String collectionName) {
         // Note: this method is more of a helper method than anything.
         // The resource could call getCollection().getCollection('foo') to
         // do the same thing.
         return this.collection.getCollection(collectionName);
    }
}

