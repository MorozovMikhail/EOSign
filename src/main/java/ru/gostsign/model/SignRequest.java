package ru.gostsign.model;

import lombok.Data;

@Data
public class SignRequest {
    private String surname;
    private String givenName;
    private String title;
    private String organizationName;
    private String city;
    private String streetAddress;
    private String email;
    private String inn;
    private String ogrn;
    
    // Поля для динамических данных штампа
    private String stampOrganizationName;
    private String stampDirector;
    private String stampInn;
    private String stampValidityPeriod;
} 