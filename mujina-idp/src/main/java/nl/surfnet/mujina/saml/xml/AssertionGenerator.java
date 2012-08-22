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


import nl.surfnet.mujina.model.AuthenticationMethod;
import nl.surfnet.mujina.model.IdpConfiguration;
import nl.surfnet.mujina.model.SimpleAuthentication;
import nl.surfnet.mujina.saml.AssertionImpl;
import nl.surfnet.mujina.util.IDService;
import nl.surfnet.mujina.util.TimeService;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;

import java.util.HashMap;
import java.util.Map;

public class AssertionGenerator {

    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    private final IssuerGenerator issuerGenerator;
    private final SubjectGenerator subjectGenerator;
    private final IDService idService;
    private final TimeService timeService;
    private final AuthnStatementGenerator authnStatementGenerator = new AuthnStatementGenerator();
    private final AttributeStatementGenerator attributeStatementGenerator = new AttributeStatementGenerator();
    private Credential signingCredential;
    private IdpConfiguration idpConfiguration;

    public AssertionGenerator(final Credential signingCredential, String issuingEntityName, TimeService timeService, IDService idService, IdpConfiguration idpConfiguration) {
        super();
        this.signingCredential = signingCredential;
        this.timeService = timeService;
        this.idService = idService;
        this.idpConfiguration = idpConfiguration;
        issuerGenerator = new IssuerGenerator(issuingEntityName);
        subjectGenerator = new SubjectGenerator(timeService);
    }

    public Assertion generateAssertion(String remoteIP,
                                       SimpleAuthentication authToken,
                                       String recipientAssertionConsumerURL,
                                       int validForInSeconds,
                                       String inResponseTo,
                                       DateTime authnInstant) {
        // org.apache.xml.security.utils.ElementProxy.setDefaultPrefix(namespaceURI, prefix).

        Assertion assertion = new AssertionImpl(
            SAMLConstants.SAML20_NS,
            Assertion.DEFAULT_ELEMENT_LOCAL_NAME,
            SAMLConstants.SAML20_PREFIX,
            this.idpConfiguration
        );

        Subject subject = subjectGenerator.generateSubject(
            recipientAssertionConsumerURL,
            validForInSeconds, authToken.getName(), inResponseTo, remoteIP);

        Issuer issuer = issuerGenerator.generateIssuer();

        AuthnStatement authnStatement = authnStatementGenerator.generateAuthnStatement(authnInstant);

        assertion.setIssuer(issuer);
        assertion.getAuthnStatements().add(authnStatement);
        assertion.setSubject(subject);

        // extends this
        // assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(authToken.getAuthorities()));

        final Map<String,String> attributes = new HashMap<String, String>();
        attributes.putAll(idpConfiguration.getAttributes());

        if (idpConfiguration.getAuthentication() == AuthenticationMethod.Method.ALL) {
            attributes.put("urn:mace:dir:attribute-def:uid", authToken.getName());
        }

        assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(attributes));

        assertion.setID(idService.generateID());
        assertion.setIssueInstant(timeService.getCurrentDateTime());

        return assertion;
    }
}
