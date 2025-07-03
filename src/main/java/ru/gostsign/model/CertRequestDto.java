package ru.gostsign.model;

import lombok.Data;

@Data
public class CertRequestDto {
    private String csr;
    private String fio;
    private String email;
    private String inn;
    private String ogrn;
} 