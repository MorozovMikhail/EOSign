package ru.gostsign.model;

import lombok.Data;

@Data
public class VerificationRequest {
    private String certificateBase64;
    private String signatureBase64;
    private byte[] documentBytes;
} 