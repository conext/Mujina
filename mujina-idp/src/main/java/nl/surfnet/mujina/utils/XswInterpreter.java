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

import org.apache.velocity.runtime.log.SystemLogChute;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureImpl;

/**
 * Interprets the XML Signature Wrapping configuration of objects and wires them up properly by interpreting the configuration.
 *
 * Parsing Expression Grammar:
 *
 * configuration        <- element nestedElement{2}
 * nestedElement        <- ">"* element
 * element              <- referencedSignature / assertionElement
 * assertionElement     <- "E" / "A"
 * referencedSignature  <- "S" reference*
 * reference            <- "(" assertionElement ")"
 */
public class XswInterpreter {
    private Integer position = 0;
    private String configuration;
    private Response response;
    private AssertionImpl assertion;
    private AssertionImpl evilAssertion;
    private SignatureImpl signature;
    private SamlAssemblerStrategy parent;

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
        parent = new SamlAssemblerResponseStrategy(response);

        SamlAssemblerStrategy element = parent.add(element());
        element = nestedElement(element);
        nestedElement(element);

        // Rewind
        position = 0;
        parent = null;

        return response;
    }

    public SamlAssemblerStrategy nestedElement(SamlAssemblerStrategy prevElement) {
        if (lookAhead().equals(">")) {
            consume(">");
            parent = prevElement;
        }
        return parent.add(element());
    }

    public SamlAssemblerStrategy element() {
        String nextToken = lookAhead();
        if (nextToken.equals("S")) {
            return new SamlAssemblerSignatureStrategy(referencedSignature());
        }
        else {
            return new SamlAssemblerAssertionStrategy(assertionElement());
        }
    }

    public AssertionImpl assertionElement() {
        String nextToken = lookAhead();
        if (nextToken.equals("E")) {
            consume("E");
            return evilAssertion;
        }
        else if (nextToken.equals("A")) {
            consume("A");
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
        consume("S");

        AssertionImpl assertion = this.assertion;
        if (lookAhead().equals("(")) {
            assertion = reference();
        }
        signature.getContentReferences().add(new SAMLObjectContentReference(assertion));

        return signature;
    }

    public AssertionImpl reference() {
        consume("(");
        AssertionImpl assertion = assertionElement();
        consume(")");
        return assertion;
    }

    protected String consume(String match) {
        String token = this.configuration.substring(this.position, this.position + 1);
        if (!token.equals(match)) {
            throw new RuntimeException("Unrecognized token " + token + " in input: " + configuration);
        }
        this.position++;
        return token;
    }

    protected String lookAhead() {
        Integer nextPosition = this.position;
        if (nextPosition.equals(this.configuration.length())) {
            return "";
        }
        return this.configuration.substring(this.position, this.position + 1);
    }
}
