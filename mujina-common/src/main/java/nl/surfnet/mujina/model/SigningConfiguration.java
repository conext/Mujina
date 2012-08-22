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

package nl.surfnet.mujina.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

/**
 * Signing configuration, allows you to set one of the following:
 * - NoSignature: don't use a signature
 * - NoReference: Use a signature without a reference
 * - XSW:{XSWconfig} XML Signature Wrapping vulnerability testing configuration,
 *   see also: http://www.nds.rub.de/media/nds/veroeffentlichungen/2012/08/03/BreakingSAML.pdf
 *   DSL with following symbols: E = Evil assertion, A = Assertion, S = Signature.
 *   Allows you to configure the position of each element like so:
 *   - EAS = Evil Assertion, Assertion and Signature on the same level (One Level)
 *   - E>A>S = Signature nested in the Assertion nested in the Evil Assertion (Three levels)
 *   - EA>S = Evil Assertion, then Assertion with nested Signature
 *   - Note that by default the signature references the proper assertion,
 *     but with S(E) you can make the signature reference the evil assertion.
 *     Example: S(E)>A>E
 */
@XmlRootElement
public class SigningConfiguration implements Serializable {
    private String setting;

    public String getSetting() {
        return setting;
    }

    @XmlElement
    public void setSetting(final String setting) {
        this.setting = setting;
    }
}

/**
 * { setting: "NoSignature/NoReference/XSW:EAS/E>A>S/EA>S"}
 */
