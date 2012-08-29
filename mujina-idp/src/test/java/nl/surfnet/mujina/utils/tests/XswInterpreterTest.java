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

package nl.surfnet.mujina.utils.tests;


import nl.surfnet.mujina.saml.xml.*;
import nl.surfnet.mujina.utils.XswInterpreter;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.ContentReference;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;

import static junit.framework.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
    "classpath:applicationContext-idp-config.xml",
    "classpath:applicationContext-property-mappings.xml",
    "classpath:applicationContext-spring-security.xml",
    "classpath:api-servlet.xml",
    "classpath:test-beans.xml"})
public class XswInterpreterTest {
    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    protected Response response;
    protected SignatureImpl signature;
    protected AssertionImpl assertion;
    protected AssertionImpl evilAssertion;

    @Before
    public void setUp() {
        // Note that we have our own signature building because the default OpenSAML XMLTooling Signature
        // doesn't allow for Object element, which we need to test XML Signature Wrapping attacks
        builderFactory.registerBuilder(
            Signature.DEFAULT_ELEMENT_NAME,
            new SignatureBuilder()
        );
        builderFactory.registerBuilder(
            SignatureObject.DEFAULT_ELEMENT_NAME,
            new SignatureObjectBuilder()
        );

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory
            .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        response = responseBuilder.buildObject();

        signature = (SignatureImpl) builderFactory
            .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
            .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        Document document;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();

            // Create the signature
            XMLSignature dsig = new XMLSignature(
                document,
                "",
                signature.getSignatureAlgorithm(),
                signature.getCanonicalizationAlgorithm()
            );
            signature.setXMLSignature(dsig);

            // Create the assertion
            assertion = (AssertionImpl) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
                .buildObject(Assertion.DEFAULT_ELEMENT_NAME);
            assertion.setID("righteous");
            assertion.setAdvice((Advice) builderFactory
                .getBuilder(Advice.DEFAULT_ELEMENT_NAME)
                .buildObject(Advice.DEFAULT_ELEMENT_NAME));
            AssertionMarshaller marshaller = new AssertionMarshaller();
            assertion.setDOM(marshaller.marshall(assertion, document));

            // Create the evil assertion
            evilAssertion = (AssertionImpl) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
                .buildObject(Assertion.DEFAULT_ELEMENT_NAME);
            evilAssertion.setID("evil");
            evilAssertion.setAdvice((Advice) builderFactory
                .getBuilder(Advice.DEFAULT_ELEMENT_NAME)
                .buildObject(Advice.DEFAULT_ELEMENT_NAME));
            evilAssertion.setDOM(marshaller.marshall(evilAssertion, document));

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testSiblingsEAS() {
        try {
            Response response = createInterpreter("EAS").interpret();
            assertEquals(
                "EAS: Evil assertion is first",
                response.getAssertions().get(0).getID(),
                evilAssertion.getID()
            );
            assertEquals(
                "EAS: Proper assertion is second",
                response.getAssertions().get(1).getID(),
                assertion.getID()
            );

            // Create the content references to the document for us to check
            XMLSignature dsig = signature.getXMLSignature();
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }
            assertEquals(
                "EAS: Signature references good assertion",
                signature.getXMLSignature().getSignedInfo().item(0).getURI(),
                '#' + assertion.getSignatureReferenceID()
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testSiblingsSEA() {
        try {
            Response response = createInterpreter("SEA").interpret();
            assertEquals(
                "SEA: Evil assertion is first",
                response.getAssertions().get(0).getID(),
                evilAssertion.getID()
            );
            assertEquals(
                "SEA: Proper assertion is second",
                response.getAssertions().get(1).getID(),
                assertion.getID()
            );

            // Create the content references to the document for us to check
            XMLSignature dsig = signature.getXMLSignature();
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }
            assertEquals(
                "SEA: Signature references good assertion",
                signature.getXMLSignature().getSignedInfo().item(0).getURI(),
                '#' + assertion.getSignatureReferenceID()
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testSibilingsWithReference() {
        try {
            Response response = createInterpreter("AES>E").interpret();

            assertEquals(
                "AES>E: Proper assertion is first",
                response.getAssertions().get(0).getID(),
                assertion.getID()
            );
            assertEquals(
                "AES>E: Evil assertion is second",
                response.getAssertions().get(1).getID(),
                evilAssertion.getID()
            );

            // Create the content references to the document for us to check
            XMLSignature dsig = signature.getXMLSignature();
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }
            assertEquals(
                "AES>E: Signature references evil assertion",
                '#' + evilAssertion.getSignatureReferenceID(),
                signature.getXMLSignature().getSignedInfo().item(0).getURI()
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testNestedSignature() {
        try {
            Response response = createInterpreter("EA(S)").interpret();

            assertEquals(
                "EA(S): Evil assertion is first",
                response.getAssertions().get(0).getID(),
                evilAssertion.getID()
            );
            assertEquals(
                "EA(S): Proper assertion is second",
                response.getAssertions().get(1).getID(),
                assertion.getID()
            );
            assertEquals(
                "EA(S): Proper assertion contains the signature",
                assertion.getSignature(),
                signature
            );

            // Create the content references to the document for us to check
            XMLSignature dsig = signature.getXMLSignature();
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }
            assertEquals(
                "EA(S): Signature references proper assertion",
                signature.getXMLSignature().getSignedInfo().item(0).getURI(),
                '#' + assertion.getSignatureReferenceID()
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testNestedEAS() {
        try {
            Response response = createInterpreter("E(A(S))").interpret();

            Assertion firstAssertion = response.getAssertions().get(0);
            assertEquals(
                "E(A(S)): Response contains the evil assertion",
                firstAssertion.getID(),
                evilAssertion.getID()
            );
            Assertion firstNestedAssertion = firstAssertion.getAdvice().getAssertions().get(0);
            assertEquals(
                "E(A(S)): Evil assertion contains the proper assertion",
                firstNestedAssertion.getID(),
                assertion.getID()
            );
            assertEquals(
                "E(A(S)): Proper assertion contains the signature",
                firstNestedAssertion.getSignature(),
                signature
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    @Test
    public void testNestedWithForwardReferenceSAE() {
        try {
            Response response = createInterpreter("S>A(A(E))").interpret();

            // Create the content references to the document for us to check
            XMLSignature dsig = signature.getXMLSignature();
            for (ContentReference contentReference : signature.getContentReferences()) {
                contentReference.createReference(dsig);
            }
            SignatureImpl responseSignature = (SignatureImpl)response.getSignature();
            assertEquals(
                "S>A(A(E)): Signature references proper assertion",
                responseSignature.getXMLSignature().getSignedInfo().item(0).getURI(),
                "#" + assertion.getSignatureReferenceID()
            );

            Assertion childAssertion = (Assertion)responseSignature.getSignatureObjects().get(0).getChildren().get(0);

            assertEquals(
                "S>A(A(E)): Proper assertion is nested under the signature",
                childAssertion.getID(),
                assertion.getID()
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    public XswInterpreter createInterpreter(String configuration) {
        return new XswInterpreter(configuration, response, assertion, evilAssertion, signature);
    }
}
