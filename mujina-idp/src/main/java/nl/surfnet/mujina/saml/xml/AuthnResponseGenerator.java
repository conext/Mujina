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

import nl.surfnet.mujina.util.IDService;
import nl.surfnet.mujina.util.TimeService;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.springframework.security.core.AuthenticationException;

public class AuthnResponseGenerator {

    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    private final IssuerGenerator issuerGenerator;
    private final IDService idService;
    private final TimeService timeService;

    StatusGenerator statusGenerator;

    public AuthnResponseGenerator(String issuingEntityName,
                                  TimeService timeService,
                                  IDService idService) {
        super();

        this.idService = idService;
        this.timeService = timeService;

        issuerGenerator = new IssuerGenerator(issuingEntityName);
        statusGenerator = new StatusGenerator();
    }

    public Response generateAuthnResponse(String recepientAssertionConsumerURL,
                                          String inResponseTo) {

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response authResponse = responseBuilder.buildObject();

        Issuer responseIssuer = issuerGenerator.generateIssuer();

        authResponse.setIssuer(responseIssuer);
        authResponse.setID(idService.generateID());
        authResponse.setIssueInstant(timeService.getCurrentDateTime());
        authResponse.setInResponseTo(inResponseTo);
        authResponse.setDestination(recepientAssertionConsumerURL);
        authResponse.setStatus(statusGenerator.generateStatus(StatusCode.SUCCESS_URI));

        return authResponse;
    }

    public Response generateAuthnResponseFailure(String recepientAssertionConsumerURL, String inResponseTo, AuthenticationException ae) {

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response authResponse = responseBuilder.buildObject();

        Issuer responseIssuer = issuerGenerator.generateIssuer();

        authResponse.setIssuer(responseIssuer);
        authResponse.setID(idService.generateID());
        authResponse.setIssueInstant(timeService.getCurrentDateTime());
        authResponse.setInResponseTo(inResponseTo);
        authResponse.setDestination(recepientAssertionConsumerURL);
        authResponse.setStatus(statusGenerator.generateStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI, ae.getClass().getName()));

        return authResponse;
    }
}