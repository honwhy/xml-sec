package com.honey.xmlsec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * for SignatureMethod, baseURI=http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160
 */
public class BcEcdsaSignatureAlgorithm extends BcSignatureAlgorithm{
    public BcEcdsaSignatureAlgorithm(Document doc, String algorithmURI) throws XMLSecurityException {
        super(doc, algorithmURI);
    }

    public BcEcdsaSignatureAlgorithm(Document doc, String algorithmURI, int hmacOutputLength) throws XMLSecurityException {
        super(doc, algorithmURI, hmacOutputLength);
    }

    public BcEcdsaSignatureAlgorithm(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    public BcEcdsaSignatureAlgorithm(Element element, String baseURI, boolean secureValidation) throws XMLSecurityException {
        super(element, baseURI, secureValidation);
    }

    @Override
    protected void initEngine() throws XMLSecurityException {
        try {
            JCEMapper.setProviderId(provider.getName());
            engine = Signature.getInstance("RIPEMD160withECDSA", provider);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSignatureException(e);
        }
    }
}
