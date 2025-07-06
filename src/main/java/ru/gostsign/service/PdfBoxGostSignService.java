package ru.gostsign.service;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import ru.gostsign.model.DocumentSignRequest;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;

@Service
public class PdfBoxGostSignService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Подписывает PDF встроенной ГОСТ-подписью (PKCS#7, CMS)
     */
    public byte[] signPdfWithGost(DocumentSignRequest request) {
        // TODO: реализовать добавление поля подписи, генерацию CMS-подписи и встраивание в PDF
        return null;
    }
} 