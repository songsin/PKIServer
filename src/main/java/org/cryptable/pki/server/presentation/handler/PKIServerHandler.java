package org.cryptable.pki.server.presentation.handler;

import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cryptable.pki.server.business.ProcessCertification;
import org.cryptable.pki.server.business.ProcessInitialization;
import org.cryptable.pki.server.business.ProcessKeyUpdate;
import org.cryptable.pki.server.business.ProcessRevocation;
import org.cryptable.pki.util.PKIKeyStore;
import org.cryptable.pki.util.PKIKeyStoreSingleton;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.QueryStringDecoder;

import static io.netty.handler.codec.http.HttpHeaders.Names.*;
import static io.netty.handler.codec.http.HttpHeaders.*;
import static io.netty.handler.codec.http.HttpResponseStatus.*;
import static io.netty.handler.codec.http.HttpVersion.*;

import java.io.IOException;
import java.util.Date;

/**
 * Our simple asynchronous PKI HTTPServer
 *
 * User: davidtillemans
 * Date: 8/06/13
 * Time: 14:35
 * To change this template use File | Settings | File Templates.
 */
public class PKIServerHandler extends ChannelInboundHandlerAdapter {

    private PKIKeyStore pkiKeyStore;

    private FullHttpRequest fullHttpRequest;

    private byte[] buf;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {

		FullHttpResponse out = null;

		try {
			out = messageReceived(ctx, msg);

		} finally {
			ctx.write(out);
            ctx.flush();
		}
	}


    private FullHttpResponse messageReceived(ChannelHandlerContext ctx, Object msg) {
    	
    	if (msg instanceof FullHttpRequest) {
    		fullHttpRequest = (FullHttpRequest) msg;
    		
            QueryStringDecoder queryStringDecoder = new QueryStringDecoder(fullHttpRequest.getUri());

            String host = HttpHeaders.getHost(fullHttpRequest, "unknown");
            String contentType = HttpHeaders.getHeader(fullHttpRequest, "Content-Type");
            HttpMethod method = fullHttpRequest.getMethod();

            if ((method == HttpMethod.POST) &&
                queryStringDecoder.path().equals("/cmp"))
                buf = processPKIMessage(fullHttpRequest.content().array());
            else
                doError();

            return writeResponse(fullHttpRequest);
    	}
    	
    	return null;
    }

    private FullHttpResponse writeResponse(HttpObject currentObj) {

    	// Decide whether to close the connection or not.
        boolean keepAlive = isKeepAlive(fullHttpRequest);

        // Build the response object.
    	FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, 
    			currentObj.getDecoderResult().isSuccess() ? OK : BAD_REQUEST, 
    			Unpooled.copiedBuffer(buf));
        response.headers().set(CONTENT_TYPE, "application/pkixcmp");

        if (keepAlive) {
            // Add 'Content-Length' header only for a keep-alive connection.
            response.headers().set(CONTENT_LENGTH, response.content().readableBytes());
            // Add keep alive header as per:
            // - http://www.w3.org/Protocols/HTTP/1.1/draft-ietf-http-v11-spec-01.html#Connection
            response.headers().set(CONNECTION, HttpHeaders.Values.KEEP_ALIVE);
        }

        // Write the response.
        return response;
        
    }

    private byte[] doError() {
        //TODO: Implementation
        //To change body of created methods use File | Settings | File Templates.
        return null;
    }

    private byte[] createProtectedPKIMessage(PKIBody pkiBody, byte[] senderNonce) throws CMPException, OperatorCreationException, IOException {

        byte[] recipientNonce = new byte[64];
        pkiKeyStore.getSecureRandom().nextBytes(recipientNonce);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(pkiKeyStore.getProvider()).build(pkiKeyStore.getSenderPrivateKey());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStore.getSenderCertificate())),
                new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStore.getRecipientCertificate())))
                .setMessageTime(new Date())
                .setSenderNonce(senderNonce)
                .setRecipNonce(recipientNonce)
                .setBody(pkiBody)
                .build(signer);

        return message.toASN1Structure().getEncoded();
    }

    /**
     * process incomming PKIMessage
     *
     * @param array
     */
    private byte[] processPKIMessage(byte[] array) {
        byte[] result = null;

        pkiKeyStore = PKIKeyStoreSingleton.getInstance();

        try {
            PKIBody pkiBody = null;

            ProtectedPKIMessage pkiMessage = new ProtectedPKIMessage(new GeneralPKIMessage(array));

            /* Verify Message */
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(pkiKeyStore.getProvider())
                    .build(pkiKeyStore.getRecipientCertificate());
            pkiMessage.verify(verifierProvider);

            /* process kind of message */
            switch (pkiMessage.getBody().getType()) {
                case PKIBody.TYPE_INIT_REQ:
                    // pkiBody = new ProcessInitialization(pkiKeyStore).initialize(pkiMessage.getBody()).getResponse();
                    break;
                case PKIBody.TYPE_CERT_REQ:
                    // pkiBody = new ProcessCertification(pkiKeyStore).initialize(pkiMessage.getBody()).getResponse();
                    break;
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    pkiBody = new ProcessKeyUpdate(pkiKeyStore).initialize(pkiMessage.getBody()).getResponse();
                    break;
                case PKIBody.TYPE_REVOCATION_REQ:
                    pkiBody = new ProcessRevocation(pkiKeyStore).initialize(pkiMessage.getBody()).getResponse();
                    break;
                default:
                    doError();
            }

            result = createProtectedPKIMessage(pkiBody, pkiMessage.getHeader().getSenderNonce().getOctets());

        } catch (Exception e) {
            e.printStackTrace();
            result = doError();
        }

        return result;
    }
}
