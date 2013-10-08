package org.projectodd.restafari.container;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;

import org.projectodd.restafari.container.requests.BaseRequest;
import org.projectodd.restafari.container.requests.GetCollectionRequest;
import org.projectodd.restafari.container.requests.GetResourceRequest;
import org.projectodd.restafari.container.responses.ErrorResponse;
import org.projectodd.restafari.container.responses.NoSuchCollectionResponse;
import org.projectodd.restafari.spi.Responder;

public class ContainerHandler extends ChannelDuplexHandler {

    public ContainerHandler(Container container) {
        this.container = container;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        System.err.println( "container: " + msg );
        if (msg instanceof GetCollectionRequest) {
            dispatchGetCollectionRequest( ctx, (GetCollectionRequest) msg );
        } else if ( msg instanceof GetResourceRequest ) {
            dispatchGetResourceRequest( ctx, (GetResourceRequest) msg );
        }
    }

    protected void dispatchGetCollectionRequest(ChannelHandlerContext ctx, GetCollectionRequest msg) {
        Holder holder = this.container.getResourceController(msg.getType());
        if (holder == null) {
            ctx.pipeline().write(new NoSuchCollectionResponse(msg.getMimeType(), msg.getType()));
            ctx.pipeline().flush();
        } else {
            holder.getResourceController().getResources(null, msg.getCollectionName(), msg, createResponder(msg, ctx ) );
        }
    }
    
    protected void dispatchGetResourceRequest(ChannelHandlerContext ctx, GetResourceRequest msg) {
        Holder holder = this.container.getResourceController(msg.getType());
        if (holder == null) {
            ctx.pipeline().write(new NoSuchCollectionResponse(msg.getMimeType(), msg.getType()));
            ctx.pipeline().flush();
        } else {
            holder.getResourceController().getResource(null, msg.getCollectionName(), msg.getResourceId(), createResponder(msg, ctx) );
        }
        
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace(System.err);
        ctx.pipeline().write(new ErrorResponse(cause.getMessage()));
        ctx.pipeline().flush();
    }

    protected Responder createResponder(BaseRequest request, ChannelHandlerContext ctx) {
        return this.container.createResponder( request.getType(), request.getMimeType(), ctx );
    }


    private Container container;
}
