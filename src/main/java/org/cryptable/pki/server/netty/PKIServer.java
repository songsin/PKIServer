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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.*;
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
 */
public class PKIServer  {

    final Logger logger = LoggerFactory.getLogger(PKIServer.class);

    private final int port;

    /**
     * Setup the PKI Server using port
     *
     * @param port The port the PKIServer listens to
     */
    public PKIServer(int port) {
        this.port = port;
    }

    /**
     * Initializes the PKI Server, loading the Key pairs for authentication and communication
     *
     * @return
     * @throws UnrecoverableKeyException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public PKIServer init() throws UnrecoverableKeyException, NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {

        FileInputStream fileInputStream = new FileInputStream("keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(fileInputStream, "system".toCharArray());

        PrivateKey  communicationPrivateKey = (PrivateKey)keyStore.getKey("COMM", "ca-system".toCharArray());
        Certificate communicationPublicKey = keyStore.getCertificate("COMM");
        PrivateKey  caPrivateKey = (PrivateKey)keyStore.getKey("CA", "ca-system".toCharArray());
        Certificate caPublicKey = keyStore.getCertificate("CA");
        PKIKeyStoreSingleton.init( communicationPrivateKey,
                communicationPublicKey,
                caPrivateKey,
                caPublicKey,
                keyStore.getCertificate("RA"),
                keyStore.getCertificateChain("CA"),
                "BC",
                "SHA1PRNG");

        fileInputStream.close();

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
    public static void main(String[] args) throws UnrecoverableKeyException, NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {

        int port;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 8080;
        }

        new PKIServer(port).init().run();
    }

}
