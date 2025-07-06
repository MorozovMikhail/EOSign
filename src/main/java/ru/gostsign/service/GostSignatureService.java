package ru.gostsign.service;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import ru.gostsign.model.SignRequest;
import ru.gostsign.model.DocumentSignRequest;
import ru.gostsign.model.VerificationRequest;
import ru.gostsign.model.VerificationResult;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

@Service
public class GostSignatureService {
    @Autowired
    private PdfSignService pdfSignService;
    
    // Храним последнюю сгенерированную ключевую пару для тестирования
    private KeyPair lastGeneratedKeyPair;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 1. Создание подписи - генерирует ключевую пару и сертификат
     */
    public byte[] createSignature(SignRequest request) {
        try {
            // Генерация ключевой пары ГОСТ 34.10-2012 (256 бит)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("Tc26-Gost-3410-12-256-paramSetA");
            kpg.initialize(ecSpec, new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            
            // Сохраняем ключевую пару для последующего использования
            this.lastGeneratedKeyPair = keyPair;

            // Distinguished Name (DN) для сертификата
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            if (request.getSurname() != null && !request.getSurname().isEmpty())
                nameBuilder.addRDN(BCStyle.SURNAME, request.getSurname());
            if (request.getGivenName() != null && !request.getGivenName().isEmpty())
                nameBuilder.addRDN(BCStyle.GIVENNAME, request.getGivenName());
            if (request.getTitle() != null && !request.getTitle().isEmpty())
                nameBuilder.addRDN(BCStyle.T, request.getTitle());
            if (request.getOrganizationName() != null && !request.getOrganizationName().isEmpty())
                nameBuilder.addRDN(BCStyle.O, request.getOrganizationName());
            if (request.getCity() != null && !request.getCity().isEmpty()) {
                nameBuilder.addRDN(BCStyle.L, request.getCity());
                nameBuilder.addRDN(BCStyle.ST, request.getCity());
            }
            nameBuilder.addRDN(BCStyle.C, "RU");
            if (request.getEmail() != null && !request.getEmail().isEmpty())
                nameBuilder.addRDN(BCStyle.E, request.getEmail());
            if (request.getInn() != null && !request.getInn().isEmpty())
                nameBuilder.addRDN(new ASN1ObjectIdentifier("1.2.643.3.131.1.1"), request.getInn());
            if (request.getOgrn() != null && !request.getOgrn().isEmpty())
                nameBuilder.addRDN(new ASN1ObjectIdentifier("1.2.643.100.1"), request.getOgrn());
            X500Name subject = nameBuilder.build();

            // Создание самоподписанного сертификата X.509
            Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
            Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            );
            ContentSigner signer = new JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-256")
                    .setProvider("BC").build(keyPair.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(signer));

            // Архивируем сертификат и ключ
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(baos)) {
                // Сертификат
                zip.putArchiveEntry(new ZipArchiveEntry("certificate.cer"));
                zip.write(cert.getEncoded());
                zip.closeArchiveEntry();
                // Приватный ключ (PKCS#8 DER)
                byte[] pkcs8 = keyPair.getPrivate().getEncoded();
                zip.putArchiveEntry(new ZipArchiveEntry("private_key.der"));
                zip.write(pkcs8);
                zip.closeArchiveEntry();
            }
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new RuntimeException("Ошибка при создании подписи: " + e.getMessage(), e);
        }
    }

    /**
     * Получение последнего сгенерированного приватного ключа в Base64
     */
    public String getLastPrivateKeyBase64() {
        if (lastGeneratedKeyPair != null) {
            return Base64.getEncoder().encodeToString(lastGeneratedKeyPair.getPrivate().getEncoded());
        }
        return null;
    }

    /**
     * 2. Подписание документа - подписывает предоставленный документ
     */
    public byte[] signDocument(DocumentSignRequest request) {
        try {
            // Проверяем, является ли документ PDF
            if (isPdfDocument(request.getDocumentBytes())) {
                // Подписываем PDF с штампом и логотипом
                return pdfSignService.signPdfDocument(request);
            } else {
                // Обычное подписание документа
                return signRegularDocument(request);
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при подписании документа: " + e.getMessage(), e);
        }
    }

    /**
     * 2a. Подписание документа с возвратом PDF с штампом и отдельной подписи
     */
    public byte[] signDocumentWithSignature(DocumentSignRequest request) {
        try {
            // Проверяем, является ли документ PDF
            if (isPdfDocument(request.getDocumentBytes())) {
                // Подписываем PDF с штампом и возвращаем ZIP с PDF и подписью
                return pdfSignService.signPdfDocumentWithSignature(request);
            } else {
                // Обычное подписание документа
                return signRegularDocumentWithSignature(request);
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при подписании документа: " + e.getMessage(), e);
        }
    }

    /**
     * 2b. Добавление штампа к документу (без подписи)
     */
    public byte[] addStampToDocument(DocumentSignRequest request) {
        try {
            // Проверяем, является ли документ PDF
            if (isPdfDocument(request.getDocumentBytes())) {
                // Добавляем только штамп к PDF
                return pdfSignService.addStampToPdfOnly(request);
            } else {
                throw new RuntimeException("Добавление штампа поддерживается только для PDF документов");
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при добавлении штампа: " + e.getMessage(), e);
        }
    }

    /**
     * Подписание обычного документа (не PDF)
     */
    private byte[] signRegularDocument(DocumentSignRequest request) throws Exception {
        // Декодируем приватный ключ
        byte[] privateKeyBytes = Base64.getDecoder().decode(request.getPrivateKeyBase64());
        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Создаем подпись документа
        Signature signature = Signature.getInstance("GOST3411WITHECGOST3410-2012-256", "BC");
        signature.initSign(privateKey);
        signature.update(request.getDocumentBytes());
        byte[] signatureBytes = signature.sign();

        // Возвращаем подпись в Base64
        return Base64.getEncoder().encode(signatureBytes);
    }

    /**
     * Подписание обычного документа с возвратом ZIP архива
     */
    private byte[] signRegularDocumentWithSignature(DocumentSignRequest request) throws Exception {
        // Декодируем приватный ключ
        byte[] privateKeyBytes = Base64.getDecoder().decode(request.getPrivateKeyBase64());
        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Создаем подпись документа
        Signature signature = Signature.getInstance("GOST3411WITHECGOST3410-2012-256", "BC");
        signature.initSign(privateKey);
        signature.update(request.getDocumentBytes());
        byte[] signatureBytes = signature.sign();

        // Создаем ZIP архив с документом и подписью
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(baos)) {
            // Оригинальный документ
            zip.putArchiveEntry(new ZipArchiveEntry("document.bin"));
            zip.write(request.getDocumentBytes());
            zip.closeArchiveEntry();
            
            // Подпись в Base64
            zip.putArchiveEntry(new ZipArchiveEntry("signature.txt"));
            zip.write(Base64.getEncoder().encode(signatureBytes));
            zip.closeArchiveEntry();
            zip.finish(); // <--- добавлено
        }
        return baos.toByteArray();
    }

    /**
     * Проверка, является ли документ PDF
     */
    private boolean isPdfDocument(byte[] documentBytes) {
        if (documentBytes.length < 4) return false;
        // PDF файлы начинаются с "%PDF"
        return documentBytes[0] == 0x25 && documentBytes[1] == 0x50 && 
               documentBytes[2] == 0x44 && documentBytes[3] == 0x46;
    }

    /**
     * 3. Проверка подписи и подписанного документа
     */
    public VerificationResult verifySignature(VerificationRequest request) {
        try {
            // Проверяем, является ли документ PDF
            if (isPdfDocument(request.getDocumentBytes())) {
                // Для PDF документов проверяем обычную подпись (так как подпись отдельная)
                return verifyRegularSignature(request);
            } else {
                // Проверяем обычную подпись
                return verifyRegularSignature(request);
            }
        } catch (Exception e) {
            return new VerificationResult(false, false, 
                "Ошибка при проверке подписи: " + e.getMessage());
        }
    }

    /**
     * Проверка обычной подписи (не PDF)
     */
    private VerificationResult verifyRegularSignature(VerificationRequest request) throws Exception {
        // Декодируем сертификат
        byte[] certBytes = Base64.getDecoder().decode(request.getCertificateBase64());
        java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

        // Декодируем подпись
        byte[] signatureBytes = Base64.getDecoder().decode(request.getSignatureBase64());

        // Проверяем подпись
        Signature signature = Signature.getInstance("GOST3411WITHECGOST3410-2012-256", "BC");
        signature.initVerify(certificate.getPublicKey());
        signature.update(request.getDocumentBytes());
        boolean isValid = signature.verify(signatureBytes);

        // Проверяем сертификат
        boolean isCertificateValid = false;
        try {
            certificate.checkValidity();
            isCertificateValid = true;
        } catch (Exception e) {
            // Сертификат недействителен
        }

        // Формируем понятное сообщение
        String message = buildVerificationMessage(isValid, isCertificateValid, certificate);
        
        // Добавляем отладочную информацию
        System.out.println("DEBUG: Подпись валидна: " + isValid);
        System.out.println("DEBUG: Сертификат валиден: " + isCertificateValid);
        System.out.println("DEBUG: Размер документа: " + request.getDocumentBytes().length + " байт");
        System.out.println("DEBUG: Размер подписи: " + signatureBytes.length + " байт");
        
        return new VerificationResult(isValid, isCertificateValid, message);
    }

    /**
     * Формирование понятного сообщения о результате проверки
     */
    private String buildVerificationMessage(boolean isValid, boolean isCertificateValid, X509Certificate certificate) {
        StringBuilder message = new StringBuilder();
        
        if (isValid) {
            message.append("[OK] Подпись ВАЛИДНА\n");
        } else {
            message.append("[ERROR] Подпись НЕВАЛИДНА\n");
        }
        
        if (isCertificateValid) {
            message.append("[OK] Сертификат ДЕЙСТВИТЕЛЕН\n");
        } else {
            message.append("[ERROR] Сертификат НЕДЕЙСТВИТЕЛЕН\n");
        }
        
        if (certificate != null) {
            message.append("[INFO] Информация о сертификате:\n");
            message.append("   Владелец: ").append(certificate.getSubjectDN()).append("\n");
            message.append("   Издатель: ").append(certificate.getIssuerDN()).append("\n");
            message.append("   Действителен с: ").append(certificate.getNotBefore()).append("\n");
            message.append("   Действителен до: ").append(certificate.getNotAfter()).append("\n");
        }
        
        return message.toString();
    }
} 