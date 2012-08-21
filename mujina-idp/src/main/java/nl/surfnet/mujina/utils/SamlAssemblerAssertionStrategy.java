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

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.AdviceImpl;

public class SamlAssemblerAssertionStrategy implements SamlAssemblerStrategy {
    private Assertion assertion;

    public SamlAssemblerAssertionStrategy(Assertion assertion) {
        this.assertion = assertion;
    }

    public Assertion getAssertion() {
        return assertion;
    }

    public SamlAssemblerStrategy add(SamlAssemblerAssertionStrategy element) {
        assertion.getAdvice().getAssertions().add(element.getAssertion());
        return element;
    }

    public SamlAssemblerStrategy add(SamlAssemblerSignatureStrategy element) {
        assertion.setSignature(element.getSignature());
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