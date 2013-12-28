package org.cryptable.pki.server.persistence.profile.jaxb;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * Date parser for usage in profile parsing
 *
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 23:03
 */
public class DateAdapter extends XmlAdapter<String, DateTime> {

    private DateTimeFormatter dateFormat = DateTimeFormat.forPattern("yyyyMMddHHmmss");

    @Override
    public String marshal(DateTime v) throws Exception {
        return dateFormat.print(v);
    }

    @Override
    public DateTime unmarshal(String v) throws Exception {
        return dateFormat.parseDateTime(v);
    }

}
