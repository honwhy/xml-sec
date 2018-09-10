package com.honey.xmlsec;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;

@RunWith(SpringRunner.class)
@SpringBootTest
public class XmlSecApplicationTests {

	@Test
	public void contextLoads() {
	}
	private static final String BASEDIR = System.getProperty("basedir");
	private static final String SEP = System.getProperty("file.separator");
	private static final String ECDSA_JKS =
			"src/test/resources/ecdsa.jks";
	private static final String ECDSA_JKS_PASSWORD = "security";
	private static KeyPair keyPair;
	static {
		try {
			BouncyCastleProvider provider = new BouncyCastleProvider();
			Security.addProvider(provider);
			keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			Init.init();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	public static void main(String[] args) throws Exception{
		SpringApplication.run(XmlSecApplication.class, args);

		MyUtil myUtil = new MyUtil();
		FileInputStream fis = null;
		if (BASEDIR != null && !"".equals(BASEDIR)) {
			fis = new FileInputStream(BASEDIR + SEP +
					"src/test/resources/sample.xml");
		} else {
			fis = new FileInputStream("src/test/resources/sample.xml");
		}
		String body = getFileContent(fis, "utf-8");
		//String signedXml = myUtil.signWithKeyPair(body, keyPair);
		//System.out.println(signedXml);

		//boolean validate = myUtil.verify(signedXml);
		//System.out.println(validate);
		/* doSignWithCert */
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream fis2 = null;
		if (BASEDIR != null && !"".equals(BASEDIR)) {
			fis = new FileInputStream(BASEDIR + SEP +
					"src/test/resources/transmitter.jks");
		} else {
			fis = new FileInputStream("src/test/resources/transmitter.jks");
		}
		ks.load(fis, "default".toCharArray());
		PrivateKey privateKey = (PrivateKey) ks.getKey("transmitter", "default".toCharArray());
		X509Certificate signingCert = (X509Certificate) ks.getCertificate("transmitter");

		//String signed2 = myUtil.signWithCert(body, privateKey, signingCert);
		//System.out.println(signed2);
		//boolean validate2 = myUtil.verify(signed2);
		//System.out.println(validate2);
		// ecdsa
		KeyStore keyStore;
		keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(ECDSA_JKS), ECDSA_JKS_PASSWORD.toCharArray());
		PrivateKey privateKey2 =
				(PrivateKey)keyStore.getKey("ECDSA", ECDSA_JKS_PASSWORD.toCharArray());

		X509Certificate x509 = (X509Certificate)keyStore.getCertificate("ECDSA");
		String signed3 = myUtil.signWithCertEcdsa(body, privateKey2, x509);
		System.err.println(signed3);
		boolean validate3 = myUtil.verify(signed3);
		System.err.println(validate3);
		/** close streams */
		fis.close();
		//fis2.close();
	}
	public static String getFileContent(
			FileInputStream fis,
			String          encoding ) throws IOException
	{
		try( BufferedReader br =
					 new BufferedReader( new InputStreamReader(fis, encoding )))
		{
			StringBuilder sb = new StringBuilder();
			String line;
			while(( line = br.readLine()) != null ) {
				sb.append( line );
				sb.append( '\n' );
			}
			return sb.toString();
		}
	}

	private static boolean doVerify(String signedXML) throws Exception {
		Document doc = null;
		try (InputStream is = new ByteArrayInputStream(signedXML.getBytes(Charset.forName("utf-8")))) {
			doc = MyXMLUtils.read(is, false);
		}

		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();
		xpath.setNamespaceContext(new DSNamespaceContext());

		String expression = "//ds:Signature[1]";
		Element sigElement =
				(Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
		XMLSignature signature = new XMLSignature(sigElement, "");

		signature.addResourceResolver(new XPointerResourceResolver(sigElement));

		KeyInfo ki = signature.getKeyInfo();
		if (ki == null) {
			throw new RuntimeException("No keyinfo");
		}
		X509Certificate cert = signature.getKeyInfo().getX509Certificate();

		if (cert == null) {
			throw new RuntimeException("No certificate");
		}
		return signature.checkSignatureValue(cert);
	}
}
