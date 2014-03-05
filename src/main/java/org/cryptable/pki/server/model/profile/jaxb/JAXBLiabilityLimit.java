package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Liability_Limit>
 *   <Amount>10000</Amount>
 *   <Exponent>1</Exponent>
 *   <Currency_Code>978</Currency_Code>
 * </Liability_Limit>
 *
 * Author: davidtillemans
 * Date: 3/03/14
 * Hour: 18:41
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBLiabilityLimit {

    @XmlElement(name="Amount")
    private Integer amount;

    @XmlElement(name="Exponent")
    private Integer exponent;

    @XmlElement(name="Currency_Code")
    private Integer currencyCode;

    public Integer getAmount() {
        return amount;
    }

    public void setAmount(Integer amount) {
        this.amount = amount;
    }

    public Integer getExponent() {
        return exponent;
    }

    public void setExponent(Integer exponent) {
        this.exponent = exponent;
    }

    public Integer getCurrencyCode() {
        return currencyCode;
    }

    public void setCurrencyCode(Integer currencyCode) {
        this.currencyCode = currencyCode;
    }
}
