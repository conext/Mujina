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

import nl.surfnet.mujina.model.IdpConfiguration;
import nl.surfnet.mujina.model.SimpleAuthentication;
import nl.surfnet.mujina.saml.xml.*;
import nl.surfnet.mujina.spring.AuthnRequestInfo;
import nl.surfnet.mujina.util.IDService;
import nl.surfnet.mujina.util.TimeService;
import nl.surfnet.mujina.utils.XswInterpreter;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.HttpRequestHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SSOSuccessAuthnResponder implements HttpRequestHandler {
    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    private final TimeService timeService;
    private final IDService idService;
    private int responseValidityTimeInSeconds;
    private final BindingAdapter adapter;
    private CredentialResolver credentialResolver;

    @Autowired
    IdpConfiguration idpConfiguration;

    private final static Logger logger = LoggerFactory
            .getLogger(SSOSuccessAuthnResponder.class);


    public SSOSuccessAuthnResponder(TimeService timeService,
                                    IDService idService,
                                    BindingAdapter adapter,
                                    CredentialResolver credentialResolver) {
        super();
        this.timeService = timeService;
        this.idService = idService;
        this.adapter = adapter;
        this.credentialResolver = credentialResolver;
    }


    @Required
    public void setResponseValidityTimeInSeconds(int responseValidityTimeInSeconds) {
        this.responseValidityTimeInSeconds = responseValidityTimeInSeconds;
    }

    @Override
    public void handleRequest(HttpServletRequest request,
                              HttpServletResponse response) throws ServletException, IOException {
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

        AuthnRequestInfo info = (AuthnRequestInfo) request.getSession().getAttribute(AuthnRequestInfo.class.getName());

        if (info == null) {
            logger.warn("Could not find AuthnRequest on the request.  Responding with SC_FORBIDDEN.");
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        logger.debug("AuthnRequestInfo: {}", info);

        SimpleAuthentication authToken = (SimpleAuthentication) SecurityContextHolder.getContext().getAuthentication();
        DateTime authnInstant = new DateTime(request.getSession().getCreationTime());

        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(idpConfiguration.getEntityID()));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        Credential signingCredential = null;
        try {
            signingCredential = credentialResolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.warn("Unable to resolve EntityID while signing", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        Validate.notNull(signingCredential);

        AuthnResponseGenerator authnResponseGenerator = new AuthnResponseGenerator(
            idpConfiguration.getEntityID(),
            timeService,
            idService
        );

        Response authResponse = authnResponseGenerator.generateAuthnResponse(
            info.getAssertionConsumerURL(),
            info.getAuthnRequestID()
        );

        AssertionGenerator assertionGenerator = new AssertionGenerator(
            signingCredential,
            idpConfiguration.getEntityID(),
            timeService,
            idService,
            idpConfiguration
        );
        AssertionImpl assertion = (AssertionImpl) assertionGenerator.generateAssertion(
            request.getRemoteAddr(),
            authToken,
            info.getAssertionConsumerURL(),
            responseValidityTimeInSeconds,
            info.getAuthnRequestID(),
            authnInstant
        );

        SignatureImpl assertionSignature = (SignatureImpl) org.opensaml.Configuration.getBuilderFactory()
            .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
            .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        assertionSignature.setSigningCredential(signingCredential);
        assertionSignature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        assertionSignature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        if (idpConfiguration.getXswConfiguration().isEmpty()) {
            // Default configuration
            if (!this.idpConfiguration.getDisableSignature()) {
                assertion.setSignature(assertionSignature);

                try {
                    org.opensaml.Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
                } catch (MarshallingException e) {
                    e.printStackTrace();
                }
                try {
                    Signer.signObject(assertionSignature);
                } catch (SignatureException e) {
                    e.printStackTrace();
                }
            }
            authResponse.getAssertions().add(assertion);
        }
        else {
            AssertionImpl evilAssertion = (AssertionImpl) assertionGenerator.generateAssertion(
                request.getRemoteAddr(),
                authToken,
                info.getAssertionConsumerURL(),
                responseValidityTimeInSeconds,
                info.getAuthnRequestID(),
                authnInstant
            );

            // To easily tell the assertions apart we set the ID of this one to something evil
            evilAssertion.setID("i-am-evil");

            // Set the UID to 'mallory'
            XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
            XSString newUidAttribute = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            newUidAttribute.setValue("mallory");
            evilAssertion.getAttributeStatements().get(0)
                .getAttributes().get(0)
                    .getAttributeValues().set(0, newUidAttribute);

            // Interpret the XML Signature Wrapping configuration that is set and use the configured response.
            XswInterpreter interpreter = new XswInterpreter(
                idpConfiguration.getXswConfiguration(),
                authResponse,
                assertion,
                evilAssertion,
                assertionSignature
            );
            authResponse = interpreter.interpret();
        }

        EndpointGenerator endpointGenerator = new EndpointGenerator();
        Endpoint endpoint = endpointGenerator.generateEndpoint(
            org.opensaml.saml2.metadata.AssertionConsumerService.DEFAULT_ELEMENT_NAME,
            info.getAssertionConsumerURL(),
            null
        );

        request.getSession().removeAttribute(AuthnRequestInfo.class.getName());

        //we could use a different adapter to send the response based on request issuer...
        try {
            adapter.sendSAMLMessage(authResponse, endpoint, signingCredential, response, info.getRelayState());
        } catch (MessageEncodingException mee) {
            logger.error("Exception encoding SAML message", mee);
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }
}
