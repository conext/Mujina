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

package nl.surfnet.mujina.saml;

import nl.surfnet.mujina.model.CommonConfiguration;

public class AssertionImpl extends org.opensaml.saml2.core.impl.AssertionImpl {
    private CommonConfiguration configuration;

    public AssertionImpl(String namespaceURI, String elementLocalName, String namespacePrefix, CommonConfiguration configuration) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        this.configuration = configuration;
    }

    /** {@inheritDoc} */
    public String getSignatureReferenceID(){
        return this.configuration.getDisableSignatureReference() ? getID() : null;
    }
}
