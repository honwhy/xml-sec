package com.honey.xmlsec;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public abstract class AbstractSignatureAlgorithm extends SignatureAlgorithm {

    private static org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(AbstractSignatureAlgorithm.class);

    public AbstractSignatureAlgorithm(Document doc, String algorithmURI) throws XMLSecurityException {
        super(doc, algorithmURI);
    }

    public AbstractSignatureAlgorithm(Document doc, String algorithmURI, int hmacOutputLength) throws XMLSecurityException {
        super(doc, algorithmURI, hmacOutputLength);
    }

    public AbstractSignatureAlgorithm(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    public AbstractSignatureAlgorithm(Element element, String baseURI, boolean secureValidation) throws XMLSecurityException {
        super(element, baseURI, secureValidation);
    }

    /**
     * Digests all References in the SignedInfo, calculates the signature value
     * and sets it in the SignatureValue Element.
     *
     * @param signingKey the {@link java.security.PrivateKey} or
     * {@link javax.crypto.SecretKey} that is used to sign.
     * @throws XMLSignatureException
     */
    public void doSign(Key signingKey, SignedInfo si) throws XMLSignatureException {

        if (signingKey instanceof PublicKey) {
            throw new IllegalArgumentException(
                    I18n.translate("algorithms.operationOnlyVerification")
            );
        }

        try {
            //Create a SignatureAlgorithm object
            //SignedInfo si = this.getSignedInfo();
            //SignatureAlgorithm sa = si.getSignatureAlgorithm();
            OutputStream so = null;
            try {
                // generate digest values for all References in this SignedInfo
                si.generateDigestValues();

                // initialize SignatureAlgorithm for signing
                this.initSign(signingKey);

                so = new UnsyncBufferedOutputStream(new SignerOutputStream(this));
                // get the canonicalized bytes from SignedInfo
                si.signInOctetStream(so);
            } catch (XMLSecurityException ex) {
                throw ex;
            } finally {
                if (so != null) {
                    try {
                        so.close();
                    } catch (IOException ex) {
                        if (log.isDebugEnabled()) {
                            log.debug(ex.getMessage(), ex);
                        }
                    }
                }
            }

            // set them on the SignatureValue element
            this.setSignatureValueElement(this.sign());
        } catch (XMLSignatureException ex) {
            throw ex;
        } catch (CanonicalizationException ex) {
            throw new XMLSignatureException(ex);
        } catch (InvalidCanonicalizerException ex) {
            throw new XMLSignatureException(ex);
        } catch (XMLSecurityException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /**
     * Base64 encodes and sets the bytes as the content of the SignatureValue
     * Node.
     *
     * @param bytes bytes to be used by SignatureValue before Base64 encoding
     */
    private void setSignatureValueElement(byte[] bytes) throws XMLSignatureException{
        NodeList nl = this.getDocument().getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
        if (nl.getLength() == 0) {
            throw new XMLSignatureException("SignatureValue Element not found");
        }

        Element signatureValueElement = (Element) nl.item(0);
        while (signatureValueElement.hasChildNodes()) {
            signatureValueElement.removeChild(signatureValueElement.getFirstChild());
        }

        String base64codedValue = Base64.encode(bytes);

        if (base64codedValue.length() > 76 && !XMLUtils.ignoreLineBreaks()) {
            base64codedValue = "\n" + base64codedValue + "\n";
        }

        Text t = createText(base64codedValue);
        signatureValueElement.appendChild(t);
    }

    @Override
    public abstract byte[] sign() throws XMLSignatureException;

    @Override
    public abstract void update(byte[] input) throws XMLSignatureException;

    @Override
    public abstract void update(byte input) throws XMLSignatureException;

    @Override
    public abstract void update(byte[] buf, int offset, int len) throws XMLSignatureException;

    @Override
    public abstract void initSign(Key signingKey) throws XMLSignatureException;

    @Override
    public abstract void initSign(Key signingKey, SecureRandom secureRandom) throws XMLSignatureException;

    @Override
    public abstract void initSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws XMLSignatureException;

    @Override
    public abstract void initVerify(Key verificationKey) throws XMLSignatureException;

    @Override
    public abstract boolean verify(byte[] signature) throws XMLSignatureException;
}
