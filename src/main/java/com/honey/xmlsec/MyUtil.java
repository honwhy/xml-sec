package com.honey.xmlsec;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class MyUtil {

    public String signWithKeyPair(String sourceXml, KeyPair kp) throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(sourceXml.getBytes(Charset.forName("utf-8")))) {
            doc = MyXMLUtils.read(is, false);
        }

        Element root = doc.getDocumentElement();

        Element canonElem =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
                null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
                new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        XMLSignature sig =
                new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return new String(bos.toByteArray(), "utf-8");
    }

    public boolean verify(String signedXML) throws Exception {
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
        KeyInfo ki = signature.getKeyInfo();

        if (ki == null) {
            throw new RuntimeException("No keyinfo");
        }
        PublicKey pk = signature.getKeyInfo().getPublicKey();

        if (pk == null) {
            throw new RuntimeException("No public key");
        }

        return signature.checkSignatureValue(pk);
    }

    public String signWithCert(String sourceXml, PrivateKey privateKey, X509Certificate signingCert) throws Exception {

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(sourceXml.getBytes(Charset.forName("utf-8")))) {
            doc = MyXMLUtils.read(is, false);
        }

        Element root = doc.getDocumentElement();

        Element canonElem =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
                null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
        );

        AbstractSignatureAlgorithm signatureAlgorithm =
                new BcSignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);//use BcSignatureAlgorithm
        XMLSignature sig =
                new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        //sig.addKeyInfo(signingCert);
        X509Data x509data = new X509Data(doc);
        x509data.addCertificate(signingCert);

        sig.getKeyInfo().addKeyName(signingCert.getSerialNumber().toString());
        sig.getKeyInfo().add(x509data);
        //sig.sign(privateKey);
        signatureAlgorithm.doSign(privateKey,sig.getSignedInfo());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return new String(bos.toByteArray(), "utf-8");
    }

    public String signWithCertEcdsa(String sourceXml, PrivateKey privateKey, X509Certificate signingCert) throws Exception {

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(sourceXml.getBytes(Charset.forName("utf-8")))) {
            doc = MyXMLUtils.read(is, false);
        }

        Element root = doc.getDocumentElement();

        Element canonElem =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
                null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
        );

        AbstractSignatureAlgorithm signatureAlgorithm =
                new BcEcdsaSignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160);
        XMLSignature sig =
                new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, XMLCipherParameters.RIPEMD_160);

        //sig.addKeyInfo(signingCert);
        X509Data x509data = new X509Data(doc);
        x509data.addCertificate(signingCert);

        sig.getKeyInfo().add(x509data);
        //sig.sign(privateKey);
        signatureAlgorithm.doSign(privateKey,sig.getSignedInfo());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return new String(bos.toByteArray(), "utf-8");
    }

}
