package com.honey.xmlsec;

import org.apache.xml.security.Init;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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

	private static KeyPair keyPair;
	static {
		try {
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
		String signedXml = myUtil.signWithKeyPair(body, keyPair);
		System.out.println(signedXml);

		boolean validate = myUtil.verify(signedXml);
		System.out.println(validate);
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

		String signed2 = myUtil.signWithCert(body, privateKey, signingCert);
		System.out.println(signed2);
		boolean validate2 = myUtil.verify(signed2);
		System.out.println(validate2);

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
}
