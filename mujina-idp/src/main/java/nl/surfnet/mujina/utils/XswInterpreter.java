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

import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionImpl;
import nl.surfnet.mujina.saml.xml.SignatureImpl;

/**
 * Interprets the XML Signature Wrapping configuration of objects and wires them up properly by interpreting the configuration.
 *
 * Parsing Expression Grammar:
 *
 * configuration        <- nestedElement+
 * nestedElement        <- element '(' nestedElement ')' / element
 * element              <- referencedSignature / assertionElement
 * assertionElement     <- 'E' / 'A'
 * referencedSignature  <- 'S' reference*
 * reference            <- '>' assertionElement
 */
public class XswInterpreter {
    private Integer position = 0;
    private String configuration;
    private Response response;
    private AssertionImpl assertion;
    private AssertionImpl evilAssertion;
    private SignatureImpl signature;

    public XswInterpreter(String configuration,
                            Response response,
                            AssertionImpl assertion,
                            AssertionImpl evilAssertion,
                            SignatureImpl signature) {
        this.configuration = configuration;
        this.response = response;
        this.assertion = assertion;
        this.evilAssertion = evilAssertion;
        this.signature = signature;
    }

    public Response interpret() {
        SamlAssemblerResponseStrategy parent = new SamlAssemblerResponseStrategy(response);
        // While we are not at the EndOfString
        while (this.position < this.configuration.length()) {
            parent.add(nestedElement());
        }

        // Rewind
        position = 0;

        return response;
    }

    public SamlAssemblerStrategy nestedElement() {
        SamlAssemblerStrategy element = element();
        if (lookAhead() == null || !lookAhead().equals('(')) {
            return element;
        }

        consume('(');
        element.add(nestedElement());
        consume(')');

        return element;
    }

    public SamlAssemblerStrategy element() {
        Character nextToken = lookAhead();
        if (nextToken.equals('S')) {
            return new SamlAssemblerSignatureStrategy(referencedSignature());
        }
        else {
            return new SamlAssemblerAssertionStrategy(assertionElement());
        }
    }

    public AssertionImpl assertionElement() {
        Character nextToken = lookAhead();
        if (nextToken.equals('E')) {
            consume('E');
            return evilAssertion;
        }
        else if (nextToken.equals('A')) {
            consume('A');
            return assertion;
        }
        else {
            throw new RuntimeException(
                "Unrecognized token '" +
                    nextToken +
                    "' in input: " +
                    this.configuration +
                    " with position " +
                    this.position
            );
        }
    }

    public SignatureImpl referencedSignature() {
        consume('S');

        AssertionImpl assertion = this.assertion;
        if (lookAhead() != null && lookAhead().equals('>')) {
            assertion = reference();
        }
        signature.getContentReferences().add(new SAMLObjectContentReference(assertion));

        return signature;
    }

    public AssertionImpl reference() {
        consume('>');
        return assertionElement();
    }

    protected Character consume(Character match) {
        Character token = this.configuration.charAt(this.position);
        if (!token.equals(match)) {
            throw new RuntimeException(
                "Unrecognized token " + token +
                    " in input: " + configuration +
                    " expecting: " + match +
                    " at position " + this.position
            );
        }
        this.position++;
        return token;
    }

    protected Character lookAhead() {
        Integer nextPosition = this.position;
        if (nextPosition.equals(this.configuration.length())) {
            return null;
        }
        return this.configuration.charAt(this.position);
    }
}
