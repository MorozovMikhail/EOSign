package ru.gostsign.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.gostsign.model.SignRequest;
import ru.gostsign.model.DocumentSignRequest;
import ru.gostsign.model.VerificationRequest;
import ru.gostsign.model.VerificationResult;
import ru.gostsign.service.GostSignatureService;
import ru.gostsign.service.TestPdfGenerator;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class SignController {
    private final GostSignatureService gostSignatureService;
    private final TestPdfGenerator testPdfGenerator;

    /**
     * 1. Создание подписи - генерирует ключевую пару и сертификат
     */
    @PostMapping(value = "/sign", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> createSignature(@RequestBody SignRequest request) {
        byte[] zipBytes = gostSignatureService.createSignature(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signature.zip")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(zipBytes);
    }

    /**
     * 2. Подписание документа
     */
    @PostMapping(value = "/sign-document", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> signDocument(@RequestBody DocumentSignRequest request) {
        byte[] signedDocument = gostSignatureService.signDocument(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_document.pdf")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(signedDocument);
    }

    /**
     * 2a. Подписание документа с возвратом подписи отдельно
     */
    @PostMapping(value = "/sign-document-with-signature", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> signDocumentWithSignature(@RequestBody DocumentSignRequest request) {
        byte[] result = gostSignatureService.signDocumentWithSignature(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_document_with_signature.zip")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(result);
    }

    /**
     * 2b. Добавление штампа к документу (без подписи)
     */
    @PostMapping(value = "/add-stamp", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> addStampToDocument(@RequestBody DocumentSignRequest request) {
        byte[] result = gostSignatureService.addStampToDocument(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=document_with_stamp.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(result);
    }

    /**
     * 1a. Получение последнего сгенерированного приватного ключа
     */
    @GetMapping(value = "/last-private-key")
    public ResponseEntity<String> getLastPrivateKey() {
        String privateKey = gostSignatureService.getLastPrivateKeyBase64();
        if (privateKey != null) {
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(privateKey);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * 3. Проверка подписи
     */
    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<VerificationResult> verifySignature(@RequestBody VerificationRequest request) {
        VerificationResult result = gostSignatureService.verifySignature(request);
        return ResponseEntity.ok(result);
    }

    /**
     * 4. Генерация тестового PDF
     */
    @GetMapping(value = "/test-pdf")
    public ResponseEntity<byte[]> generateTestPdf() {
        byte[] pdfBytes = testPdfGenerator.generateTestPdf();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=test_document.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfBytes);
    }
} 