/*
 * Copyright 2012 SURFnet bv, The Netherlands
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.surfnet.mujina.saml.xml;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.signature.ContentReference;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** {@inheritDoc} */
public class SignatureMarshaller extends org.opensaml.xml.signature.impl.SignatureMarshaller {
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SignatureMarshaller.class);

    /** {@inheritDoc} */
    public Element marshall(XMLObject xmlObject, Element parentElement) throws MarshallingException {
        Element signatureElement = createSignatureElement((SignatureImpl) xmlObject, parentElement.getOwnerDocument());
        XMLHelper.appendChildElement(parentElement, signatureElement);
        return signatureElement;
    }

    /** {@inheritDoc} */
    public Element marshall(XMLObject xmlObject, Document document) throws MarshallingException {
        Element signatureElement = createSignatureElement((SignatureImpl) xmlObject, document);

        Element documentRoot = document.getDocumentElement();
        if (documentRoot != null) {
            document.replaceChild(signatureElement, documentRoot);
        } else {
            document.appendChild(signatureElement);
        }

        return signatureElement;
    }

    /**
     * Creates the signature elements but does not compute the signature.
     *
     * @param signature the XMLObject to be signed
     * @param document the owning document
     *
     * @return the Signature element
     *
     * @throws MarshallingException thrown if the signature can not be constructed
     */
    private Element createSignatureElement(Signature signature, Document document) throws MarshallingException {
        log.debug("Starting to marshall {}", signature.getElementQName());

        try {
            log.debug("Creating XMLSignature object");
            XMLSignature dsig = null;
            if (signature.getHMACOutputLength() != null && SecurityHelper.isHMAC(signature.getSignatureAlgorithm())) {
                dsig = new XMLSignature(document, "", signature.getSignatureAlgorithm(), signature
                    .getHMACOutputLength(), signature.getCanonicalizationAlgorithm());
            } else {
                dsig = new XMLSignature(document, "", signature.getSignatureAlgorithm(), signature
                    .getCanonicalizationAlgorithm());
            }

            log.debug("Adding content to XMLSignature.");
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }

            log.debug("Creating Signature DOM element");
            Element signatureElement = dsig.getElement();

            if (signature.getKeyInfo() != null) {
                Marshaller keyInfoMarshaller = Configuration.getMarshallerFactory().getMarshaller(
                    KeyInfo.DEFAULT_ELEMENT_NAME);
                keyInfoMarshaller.marshall(signature.getKeyInfo(), signatureElement);
            }

            SignatureObjectMarshaller signatureObjectMarshaller = new SignatureObjectMarshaller();
            for (SignatureObjectImpl signatureObject : signature.getSignatureObjects()) {
                signatureObjectMarshaller.marshall(signatureObject, signatureElement);
            }

            ((SignatureImpl) signature).setXMLSignature(dsig);
            signature.setDOM(signatureElement);
            signature.releaseParentDOM(true);
            return signatureElement;

        } catch (XMLSecurityException e) {
            log.error("Unable to construct signature Element " + signature.getElementQName(), e);
            throw new MarshallingException("Unable to construct signature Element " + signature.getElementQName(), e);
        }
    }
}
