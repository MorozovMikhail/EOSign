package ru.gostsign.model;

import lombok.Data;

@Data
public class DocumentSignRequest {
    private String privateKeyBase64;
    private String certificateBase64;
    private byte[] documentBytes;
    
    // Поля для динамических данных штампа
    private String stampOrganizationName;
    private String stampDirector;
    private String stampInn;
    private String stampValidityPeriod;
} 