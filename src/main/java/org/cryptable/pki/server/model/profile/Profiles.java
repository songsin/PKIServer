package org.cryptable.pki.server.model.profile;

/**
 * Interface the profile data
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 09:48
 */
public interface Profiles {

    public Profile get(String profileName);

    public Profile get(int profileID);
}
