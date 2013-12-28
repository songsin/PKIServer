package org.cryptable.pki.server.persistence.profile;

import javax.persistence.*;

/**
 * Author: davidtillemans
 * Date: 23/12/13
 * Hour: 22:22
 */
@Entity
@Table(name="PROFILE")
public class Profile {

    private Integer Id;

    private byte[] profile;

    private byte[] profileSignature;

    @Id
    @Column(name="PROFILE_ID")
    public Integer getId() {
        return Id;
    }

    public void setId(Integer id) {
        Id = id;
    }

    @Lob
    @Column(name="PROFILE_BLOB")
    public byte[] getProfile() {
        return profile;
    }

    public void setProfile(byte[] profile) {
        this.profile = profile;
    }

    @Lob
    @Column(name="PROFILE_SIGNATURE")
    public byte[] getProfileSignature() {
        return profileSignature;
    }

    public void setProfileSignature(byte[] profileSignature) {
        this.profileSignature = profileSignature;
    }

}
