package com.honey.xmlsec;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class BcSignatureAlgorithm extends AbstractSignatureAlgorithm {

    protected Signature engine;
    protected static BouncyCastleProvider provider = new BouncyCastleProvider();
    public BcSignatureAlgorithm(Document doc, String algorithmURI) throws XMLSecurityException {
        super(doc, algorithmURI);
        initEngine();
    }

    public BcSignatureAlgorithm(Document doc, String algorithmURI, int hmacOutputLength) throws XMLSecurityException {
        super(doc, algorithmURI, hmacOutputLength);
        initEngine();
    }

    public BcSignatureAlgorithm(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
        initEngine();
    }

    public BcSignatureAlgorithm(Element element, String baseURI, boolean secureValidation) throws XMLSecurityException {
        super(element, baseURI, secureValidation);
        initEngine();
    }

    protected void initEngine() throws XMLSecurityException {
        try {
            engine = Signature.getInstance("SHA1withRSA", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public void update(byte[] input) throws XMLSignatureException {
        try {
            engine.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public void update(byte input) throws XMLSignatureException {
        try {
            engine.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public void update(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            engine.update(buf, offset, len);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public void initSign(Key signingKey) throws XMLSignatureException {
        try {
            engine.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void initSign(Key signingKey, SecureRandom secureRandom) throws XMLSignatureException {
        try {
            engine.initSign((PrivateKey) signingKey, secureRandom);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void initSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws XMLSignatureException {
        throw new XMLSignatureException("unsupported operation");
    }

    @Override
    public byte[] sign() throws XMLSignatureException {
        try {
            return engine.sign();
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public void initVerify(Key verificationKey) throws XMLSignatureException {
        try {
            engine.initVerify((PublicKey) verificationKey);
        } catch (InvalidKeyException e) {
            throw new XMLSignatureException(e);
        }
    }

    @Override
    public boolean verify(byte[] signature) throws XMLSignatureException {
        try {
            return engine.verify(signature);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e);
        }

    }
}
