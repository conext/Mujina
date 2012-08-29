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

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface BindingAdapter {

    public Boolean isUsedBy(HttpServletRequest request);

    public void sendSAMLMessage(SignableSAMLObject samlMessage,
                                Endpoint endpoint,
                                Credential signingCredential,
                                HttpServletResponse response,
                                String relayState
    ) throws MessageEncodingException;

    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request) throws MessageDecodingException, SecurityException;

    public String extractSAMLMessage(HttpServletRequest request);

}
