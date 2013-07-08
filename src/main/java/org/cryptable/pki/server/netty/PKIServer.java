package org.cryptable.pki.server.netty;

import org.cryptable.pki.server.presentation.handler.PKIServerHandler;
import org.cryptable.pki.util.PKIKeyStoreSingleton;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;

/**
 * The PKI Server Main class
 *
 * User: davidtillemans
 * Date: 8/06/13
 * Time: 17:41
 * To change this template use File | Settings | File Templates.
 */
public class PKIServer  {
    private final int port;

    /**
     * Setup the PKI Server using port
     *
     * @param port The port the PKIServer listens to
     */
    public PKIServer(int port) {
        this.port = port;
    }

    public PKIServer init() throws UnrecoverableKeyException, NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
    	
    	KeyStore keyStore = KeyStore.getInstance("JKS");
    	keyStore.load(new FileInputStream("keystore.jks"), "system".toCharArray());

        // TODO: 0 position change to search the corresponding certificate
    	PKIKeyStoreSingleton.init((PrivateKey) keyStore.getKey("COMM", "ca-system".toCharArray()),
                keyStore.getCertificateChain("COMM")[0],
                (PrivateKey) keyStore.getKey("CAPK", "ca-system".toCharArray()),
                keyStore.getCertificateChain("CA")[0],
                keyStore.getCertificate("RA"),
                keyStore.getCertificateChain("CA"),
                "BC",
                "SHA1PRNG");

        return this;
    }

    /**
     * start the server
     */
    public void run() {
    	EventLoopGroup bossGroup = new NioEventLoopGroup();
    	EventLoopGroup workerGroup = new NioEventLoopGroup();
    	
        ServerBootstrap bootstrap = new ServerBootstrap();

        bootstrap.group(bossGroup, workerGroup)
        	.channel(NioServerSocketChannel.class)
        	.childHandler(new ChannelInitializer<SocketChannel>() {
        		@Override
        		public void initChannel(SocketChannel ch) {
        			ch.pipeline().addLast("decoder", new HttpRequestDecoder());
        			ch.pipeline().addLast("aggregator", new HttpObjectAggregator(1048576));
        			ch.pipeline().addLast("encoder", new HttpResponseEncoder());
        			ch.pipeline().addLast("handler", new PKIServerHandler());
             		}
			});

        bootstrap.bind(new InetSocketAddress(port));
    }

    /**
     * Start the server (default port 8080)
     *
     * @param args
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws CertificateException 
     * @throws KeyStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws NoSuchProviderException 
     * @throws UnrecoverableKeyException 
     */
    public static void main(String[] args) throws UnrecoverableKeyException, NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

        int port;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 8080;
        }

        new PKIServer(port).init().run();
    }

}
