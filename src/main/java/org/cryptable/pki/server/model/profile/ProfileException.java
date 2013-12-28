package org.cryptable.pki.server.model.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The exception class when invalid profiles settings are used.
 * <p/>
 * Author: david
 * Date: 12/22/13
 * Time: 9:42 PM
 */
public class ProfileException extends Exception {
    final Logger logger = LoggerFactory.getLogger(ProfileException.class);

    public ProfileException(String s) {
        super(s);
    }
}
