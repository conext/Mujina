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

package nl.surfnet.mujina.utils;

import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;

public class SamlAssemblerSignatureStrategy implements SamlAssemblerStrategy {
    private SignatureImpl signature;

    public SamlAssemblerSignatureStrategy(SignatureImpl signature) {
        this.signature = signature;
    }

    public Signature getSignature() {
        return signature;
    }

    public SamlAssemblerStrategy add(SamlAssemblerAssertionStrategy element) {
        try {
            ObjectContainer object = new ObjectContainer(
                element.getAssertion().getDOM().getOwnerDocument()
            );
            object.appendChild(element.getAssertion().getDOM());
            signature.getXMLSignature().appendObject(object);
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return element;
    }

    public SamlAssemblerStrategy add(SamlAssemblerStrategy element) {
        if (element instanceof SamlAssemblerAssertionStrategy) {
            return add((SamlAssemblerAssertionStrategy) element);
        }
        throw new RuntimeException("Unsupported element!");
    }
}