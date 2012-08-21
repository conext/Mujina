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

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.signature.ContentReference;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureImpl;

public class SamlAssemblerResponseStrategy implements SamlAssemblerStrategy {
    private Response response;

    public SamlAssemblerResponseStrategy(Response response) {
        this.response = response;
    }

    public Response getResponse() {
        return response;
    }

    public SamlAssemblerStrategy add(SamlAssemblerAssertionStrategy element) {
        response.getAssertions().add(element.getAssertion());
        return element;
    }

    public SamlAssemblerStrategy add(SamlAssemblerSignatureStrategy element) {
        Signature signature = element.getSignature();
        response.setSignature(signature);
        return element;
    }

    public SamlAssemblerStrategy add(SamlAssemblerStrategy element) {
        if (element instanceof SamlAssemblerAssertionStrategy) {
            return add((SamlAssemblerAssertionStrategy) element);
        }
        else if (element instanceof SamlAssemblerSignatureStrategy) {
            return add((SamlAssemblerSignatureStrategy) element);
        }
        throw new RuntimeException("Unsupported element!");
    }
}
