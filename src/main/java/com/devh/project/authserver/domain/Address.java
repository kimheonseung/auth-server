package com.devh.project.authserver.domain;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Embeddable;

@Embeddable
@Getter
@Setter
public class Address {
    private String city;
    private String street;
    private String zipcode;

    @Override
    public String toString() {
        return String.format("%s시 %s로 [%s]", city, street, zipcode);
    }
}
