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

import nl.surfnet.mujina.saml.xml.SignatureImpl;
import nl.surfnet.mujina.saml.xml.SignatureObject;
import nl.surfnet.mujina.saml.xml.SignatureObjectBuilder;
import nl.surfnet.mujina.saml.xml.SignatureObjectImpl;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.Signature;

public class SamlAssemblerSignatureStrategy implements SamlAssemblerStrategy {
    private SignatureImpl signature;
    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    public SamlAssemblerSignatureStrategy(SignatureImpl signature) {
        this.signature = signature;
    }

    public Signature getSignature() {
        return signature;
    }

    public SamlAssemblerStrategy add(SamlAssemblerAssertionStrategy element) {
        try {
            SignatureObjectBuilder signatureObjectBuilder = (SignatureObjectBuilder) builderFactory.getBuilder(SignatureObject.DEFAULT_ELEMENT_NAME);
            SignatureObjectImpl signatureObject = signatureObjectBuilder.buildObject();
            signatureObject.getChildren().add(element.getAssertion());
            signature.getSignatureObjects().add(signatureObject);
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