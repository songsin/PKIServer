package org.cryptable.pki.server.persistence.pki;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.Table;

/**
 * This is the user model which contains a lot of certificates
 * <p/>
 * Author: david
 * Date: 12/22/13
 * Time: 6:30 PM
 */
@Entity
@Table(name="USER")
public class User {


    /**
     * Distinguished name of the user for its certificates
     */
    String SubjectDN;


    List<Certificate> certificateList;
}
