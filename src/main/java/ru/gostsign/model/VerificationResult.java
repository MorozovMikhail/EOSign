package ru.gostsign.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VerificationResult {
    private boolean signatureValid;
    private boolean certificateValid;
    private String message;
} 