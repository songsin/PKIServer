package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * XMLAdapter Yes/No to true/false
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 23:22
 */
class BooleanYesNoAdapter extends XmlAdapter<String, Boolean> {

    @Override
    public Boolean unmarshal(String value) {
        return value.equalsIgnoreCase("YES");
    }

    @Override
    public String marshal(Boolean value) {
        return String.valueOf(value ? "Yes" : "No");
    }
}
