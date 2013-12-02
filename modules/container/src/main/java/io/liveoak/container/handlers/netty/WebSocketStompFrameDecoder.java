package io.liveoak.container.handlers.netty;

import java.util.List;

import io.liveoak.stomp.common.StompFrameDecoder;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

/**
 * @author Bob McWhirter
 */

public class WebSocketStompFrameDecoder extends MessageToMessageDecoder<WebSocketFrame> {

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        ctx.pipeline().addAfter(ctx.name(), "stomp-frame-decoder", new StompFrameDecoder());
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, WebSocketFrame msg, List<Object> out) throws Exception {
        if (msg instanceof TextWebSocketFrame || msg instanceof BinaryWebSocketFrame) {
            out.add(msg.content().retain());
        } else {
            out.add(msg.retain());
        }
    }

}
