package org.cryptable.pki.server.model.pki;

import javax.security.cert.Certificate;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Version;

/**
 * This is the user model which contains a lot of certificates
 * <p/>
 * Author: david
 * Date: 12/22/13
 * Time: 6:30 PM
 */
@Entity
@Table(name="e_junktable")
public class User {

    /**
     * Distinguished name of the user for its certificates
     */
    String SubjectDN;


    List<Certificate> certificateList;
}
