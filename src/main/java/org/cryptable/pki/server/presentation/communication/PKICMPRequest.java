/**
 * The MIT License (MIT)
 *
 * Copyright (c) <2013> <Cryptable>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
package org.cryptable.pki.server.presentation.communication;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Class for PKICMPRequest and keeps the main components of the CA
 *
 * User: davidtillemans
 * Date: 9/06/13
 * Time: 14:03
 * To change this template use File | Settings | File Templates.
 */
public class PKICMPRequest {
    private PKIHeader pkiHeader;
    private PKIBody pkiBody;
    private List<X509Certificate> x509CertifificateList;

    public PKICMPRequest() {
        x509CertifificateList = new ArrayList<X509Certificate>();
    }

    public PKIBody getPkiBody() {
        return pkiBody;
    }

    public void setPkiBody(PKIBody pkiBody) {
        this.pkiBody = pkiBody;
    }

    public PKIHeader getPkiHeader() {
        return pkiHeader;
    }

    public void setPkiHeader(PKIHeader pkiHeader) {
        this.pkiHeader = pkiHeader;
    }

    public List<X509Certificate> getX509CertifificateList() {
        return x509CertifificateList;
    }

    public void setX509CertifificateList(List<X509Certificate> x509CertifificateList) {
        this.x509CertifificateList = x509CertifificateList;
    }

}
