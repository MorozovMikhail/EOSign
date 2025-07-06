package ru.gostsign.service;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
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
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import ru.gostsign.model.SignRequest;
import ru.gostsign.model.StampField;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;

@Service
public class GostSignService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] generateAndSign(SignRequest request) {
        try {
            // 1. Генерация ключевой пары ГОСТ 34.10-2012 (256 бит) через BouncyCastle
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("Tc26-Gost-3410-12-256-paramSetA");
            kpg.initialize(ecSpec, new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();

            // 2. Distinguished Name (DN) для сертификата
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

            // 3. Создание самоподписанного сертификата X.509 через BouncyCastle
            Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
            Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 100L); // 100 лет
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            );
            ContentSigner signer = new JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-256")
                    .setProvider("BC").build(keyPair.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(signer));

            // 4. Подписываем сообщение ГОСТ-алгоритмом через BouncyCastle
            // String message = "Подпись является усиленной неквалифицированной";
            // Signature signature = Signature.getInstance("GOST3411WITHECGOST3410-2012-256", "BC");
            // signature.initSign(keyPair.getPrivate());
            // signature.update(message.getBytes(StandardCharsets.UTF_8));
            // byte[] signBytes = signature.sign();
            // String signBase64 = Base64.getEncoder().encodeToString(signBytes);

            // 5. Архивируем сертификат и ключ
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
            throw new RuntimeException("Ошибка при генерации подписи: " + e.getMessage(), e);
        }
    }
    
    /**
     * Добавляет штамп с динамическими полями на все страницы PDF
     */
    public byte[] addStampToPdf(byte[] pdfBytes, SignRequest request) throws IOException {
        System.out.println("Начинаем добавление штампа к PDF...");
        try (PDDocument document = PDDocument.load(pdfBytes)) {
            System.out.println("PDF документ загружен, количество страниц: " + document.getNumberOfPages());
            
            // Загружаем изображение штампа
            ClassPathResource stampResource = new ClassPathResource("stamp.png");
            System.out.println("Путь к файлу штампа: " + stampResource.getFile().getAbsolutePath());
            PDImageXObject stampImage = PDImageXObject.createFromFile(stampResource.getFile().getAbsolutePath(), document);
            System.out.println("Изображение штампа загружено");
            
            // Координаты полей штампа
            Map<String, StampField> stampFields = new HashMap<>();
            stampFields.put("organizationName", new StampField("Название организации", 150, 48, 10, "#000000"));
            stampFields.put("director", new StampField("Директор", 150, 37, 10, "#000000"));
            stampFields.put("inn", new StampField("ИНН", 150, 24, 10, "#000000"));
            stampFields.put("validityPeriod", new StampField("Срок действия", 150, 14, 10, "#000000"));
            
            // Добавляем штамп на каждую страницу
            for (int i = 0; i < document.getNumberOfPages(); i++) {
                PDPage page = document.getPage(i);
                PDRectangle pageSize = page.getMediaBox();
                
                // Размеры штампа
                float stampWidth = pageSize.getWidth() * 0.30f;
                float stampHeight = stampWidth * stampImage.getHeight() / stampImage.getWidth();
                
                // Позиция штампа
                float stampX = pageSize.getWidth() - stampWidth - 20;
                float stampY = 20;
                
                try (PDPageContentStream contentStream = new PDPageContentStream(document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
                    // Добавляем изображение штампа
                    contentStream.drawImage(stampImage, stampX, stampY, stampWidth, stampHeight);
                    
                    // Добавляем динамические текстовые поля
                    addDynamicTextFields(contentStream, document, request, stampFields, stampX, stampY, stampWidth, stampHeight);
                }
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            return baos.toByteArray();
        }
    }

    private void addDynamicTextFields(PDPageContentStream contentStream, PDDocument document, SignRequest request, 
                                    Map<String, StampField> stampFields, float stampX, float stampY, 
                                    float stampWidth, float stampHeight) throws IOException {
        
        // Устанавливаем шрифт Times New Roman с поддержкой кириллицы
        PDFont font = getTimesNewRomanFont(document);
        // Цвет текста #1b1564
        java.awt.Color stampColor = new java.awt.Color(27, 21, 100);
        
        // Добавляем значения полей
        // Название организации
        if (request.getStampOrganizationName() != null && !request.getStampOrganizationName().isEmpty()) {
            StampField field = stampFields.get("organizationName");
            float x = stampX + field.getX() * stampWidth / 300;
            float y = stampY + field.getY() * stampHeight / 100;
            contentStream.setNonStrokingColor(stampColor);
            contentStream.setFont(font, Math.max(6, field.getFontSize() - 2));
            contentStream.beginText();
            contentStream.newLineAtOffset(x, y);
            contentStream.showText(request.getStampOrganizationName());
            contentStream.endText();
        }
        
        // Директор
        if (request.getStampDirector() != null && !request.getStampDirector().isEmpty()) {
            StampField field = stampFields.get("director");
            float x = stampX + field.getX() * stampWidth / 300;
            float y = stampY + field.getY() * stampHeight / 100;
            contentStream.setNonStrokingColor(stampColor);
            contentStream.setFont(font, Math.max(6, field.getFontSize() - 2));
            contentStream.beginText();
            contentStream.newLineAtOffset(x, y);
            contentStream.showText(request.getStampDirector());
            contentStream.endText();
        }
        
        // ИНН
        if (request.getStampInn() != null && !request.getStampInn().isEmpty()) {
            StampField field = stampFields.get("inn");
            float x = stampX + field.getX() * stampWidth / 300;
            float y = stampY + field.getY() * stampHeight / 100;
            contentStream.setNonStrokingColor(stampColor);
            contentStream.setFont(font, Math.max(6, field.getFontSize() - 2));
            contentStream.beginText();
            contentStream.newLineAtOffset(x, y);
            contentStream.showText(request.getStampInn()); // ИНН содержит только цифры
            contentStream.endText();
        }
        
        // Срок действия
        if (request.getStampValidityPeriod() != null && !request.getStampValidityPeriod().isEmpty()) {
            StampField field = stampFields.get("validityPeriod");
            float x = stampX + field.getX() * stampWidth / 300;
            float y = stampY + field.getY() * stampHeight / 100;
            contentStream.setNonStrokingColor(stampColor);
            contentStream.setFont(font, Math.max(6, field.getFontSize() - 2));
            contentStream.beginText();
            contentStream.newLineAtOffset(x, y);
            contentStream.showText(request.getStampValidityPeriod());
            contentStream.endText();
        }
    }

    private PDFont getTimesNewRomanFont(PDDocument document) throws IOException {
        try {
            // Пытаемся загрузить Times New Roman из системных шрифтов Windows
            System.out.println("Пытаемся загрузить Times New Roman из C:/Windows/Fonts/times.ttf");
            return PDType0Font.load(document, new File("C:/Windows/Fonts/times.ttf"));
        } catch (Exception e) {
            System.err.println("Ошибка загрузки times.ttf: " + e.getMessage());
            try {
                // Альтернативный вариант - Times New Roman Bold
                System.out.println("Пытаемся загрузить Times New Roman Bold из C:/Windows/Fonts/timesbd.ttf");
                return PDType0Font.load(document, new File("C:/Windows/Fonts/timesbd.ttf"));
            } catch (Exception e2) {
                System.err.println("Ошибка загрузки timesbd.ttf: " + e2.getMessage());
                try {
                    // Еще один вариант - Times New Roman Italic
                    System.out.println("Пытаемся загрузить Times New Roman Italic из C:/Windows/Fonts/timesi.ttf");
                    return PDType0Font.load(document, new File("C:/Windows/Fonts/timesi.ttf"));
                } catch (Exception e3) {
                    System.err.println("Ошибка загрузки timesi.ttf: " + e3.getMessage());
                    // Если ничего не получилось, используем стандартный шрифт
                    System.err.println("Не удалось загрузить Times New Roman, используем Helvetica");
                    return PDType1Font.HELVETICA;
                }
            }
        }
    }
} 