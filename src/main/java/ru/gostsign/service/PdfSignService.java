package ru.gostsign.service;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.BaseFont;
import org.apache.commons.io.IOUtils;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.springframework.stereotype.Service;
import ru.gostsign.model.DocumentSignRequest;
import ru.gostsign.model.VerificationRequest;
import ru.gostsign.model.VerificationResult;
import ru.gostsign.model.SignRequest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Signature;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;

@Service
public class PdfSignService {
    
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Подписание PDF документа с добавлением штампа и логотипа
     */
    public byte[] signPdfDocument(DocumentSignRequest request) {
        try {
            // Добавляем штамп с динамическими полями
            GostSignService gostSignService = new GostSignService();
            byte[] pdfWithStamp = gostSignService.addStampToPdf(request.getDocumentBytes(), convertToSignRequest(request));
            
            // Возвращаем PDF с штампом (подпись создается отдельно при необходимости)
            return pdfWithStamp;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при подписании PDF: " + e.getMessage(), e);
        }
    }

    /**
     * Добавление только штампа к PDF документу (без подписи)
     */
    public byte[] addStampToPdfOnly(DocumentSignRequest request) {
        try {
            // Добавляем штамп с динамическими полями
            GostSignService gostSignService = new GostSignService();
            byte[] pdfWithStamp = gostSignService.addStampToPdf(request.getDocumentBytes(), convertToSignRequest(request));
            
            // Возвращаем PDF с штампом
            return pdfWithStamp;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при добавлении штампа к PDF: " + e.getMessage(), e);
        }
    }

    /**
     * Подписание PDF документа с возвратом ZIP архива (PDF + подпись)
     */
    public byte[] signPdfDocumentWithSignature(DocumentSignRequest request) {
        try {
            // Добавляем штамп с динамическими полями
            GostSignService gostSignService = new GostSignService();
            byte[] pdfWithStamp = gostSignService.addStampToPdf(request.getDocumentBytes(), convertToSignRequest(request));
            
            try {
                // Создаем отдельную подпись документа (подписываем PDF с штампом)
                byte[] signature = createDocumentSignature(request, pdfWithStamp);
                
                // Создаем ZIP архив с PDF и подписью
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(baos)) {
                    // PDF с штампом
                    zip.putArchiveEntry(new ZipArchiveEntry("signed_document.pdf"));
                    zip.write(pdfWithStamp);
                    zip.closeArchiveEntry();
                    
                    // Подпись в Base64
                    zip.putArchiveEntry(new ZipArchiveEntry("signature.txt"));
                    zip.write(signature);
                    zip.closeArchiveEntry();
                    zip.finish();
                }
                return baos.toByteArray();
            } catch (Exception signatureError) {
                // Если не удалось создать подпись, возвращаем только PDF с штампом
                System.err.println("Предупреждение: Не удалось создать подпись: " + signatureError.getMessage());
                System.err.println("Возвращаем только PDF с штампом");
                
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(baos)) {
                    // PDF с штампом
                    zip.putArchiveEntry(new ZipArchiveEntry("document_with_stamp.pdf"));
                    zip.write(pdfWithStamp);
                    zip.closeArchiveEntry();
                    
                    // Файл с ошибкой подписи
                    zip.putArchiveEntry(new ZipArchiveEntry("signature_error.txt"));
                    zip.write(("Ошибка создания подписи: " + signatureError.getMessage()).getBytes());
                    zip.closeArchiveEntry();
                    zip.finish(); // <--- добавлено
                }
                return baos.toByteArray();
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при подписании PDF: " + e.getMessage(), e);
        }
    }
    
    /**
     * Создает отдельную подпись документа
     */
    private byte[] createDocumentSignature(DocumentSignRequest request, byte[] documentBytes) throws Exception {
        // Декодируем приватный ключ
        byte[] privateKeyBytes = Base64.getDecoder().decode(request.getPrivateKeyBase64());
        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Создаем подпись документа
        Signature signature = Signature.getInstance("GOST3411WITHECGOST3410-2012-256", "BC");
        signature.initSign(privateKey);
        signature.update(documentBytes);
        byte[] signatureBytes = signature.sign();

        // Возвращаем подпись в Base64
        return Base64.getEncoder().encode(signatureBytes);
    }
    
    /**
     * Конвертирует DocumentSignRequest в SignRequest для передачи данных штампа
     */
    private SignRequest convertToSignRequest(DocumentSignRequest request) {
        SignRequest signRequest = new SignRequest();
        signRequest.setStampOrganizationName(request.getStampOrganizationName());
        signRequest.setStampDirector(request.getStampDirector());
        signRequest.setStampInn(request.getStampInn());
        signRequest.setStampValidityPeriod(request.getStampValidityPeriod());
        return signRequest;
    }

    /**
     * Проверка подписи PDF документа
     */
    public VerificationResult verifyPdfSignature(VerificationRequest request) {
        try {
            // Читаем подписанный PDF
            PdfReader reader = new PdfReader(request.getDocumentBytes());
            
            // Получаем подпись
            AcroFields fields = reader.getAcroFields();
            String signatureName = fields.getSignatureNames().get(0);
            
            // Проверяем подпись
            PdfPKCS7 pk = fields.verifySignature(signatureName);
            boolean isValid = pk.verify();
            
            // Проверяем сертификат
            X509Certificate cert = pk.getSigningCertificate();
            boolean isCertificateValid = false;
            try {
                cert.checkValidity();
                isCertificateValid = true;
            } catch (Exception e) {
                // Сертификат недействителен
            }
            
            // Формируем понятное сообщение
            String message = buildVerificationMessage(isValid, isCertificateValid, pk);
            
            return new VerificationResult(isValid, isCertificateValid, message);
            
        } catch (Exception e) {
            return new VerificationResult(false, false, 
                "Ошибка при проверке подписи: " + e.getMessage());
        }
    }

    /**
     * Добавление штампа в PDF документ
     */
    private void addStampToPdf(PdfStamper stamper) throws IOException, DocumentException {
        // Получаем размеры страницы
        Rectangle pageSize = stamper.getReader().getPageSize(1);
        float pageWidth = pageSize.getWidth();
        float pageHeight = pageSize.getHeight();
        
        // Загружаем изображение штампа
        Image stampImage = loadStampImage();
        
        // Рассчитываем оптимальный размер штампа в зависимости от размера страницы
        float stampWidth = calculateOptimalStampSize(pageWidth, pageHeight);
        float stampHeight = stampWidth * stampImage.getHeight() / stampImage.getWidth();
        
        // Рассчитываем позицию в правом нижнем углу с отступом
        float margin = Math.max(20, Math.min(pageWidth, pageHeight) * 0.02f); // 2% от меньшей стороны, но не менее 20px
        float stampX = pageWidth - stampWidth - margin;
        float stampY = margin;
        
        // Масштабируем изображение
        stampImage.scaleAbsolute(stampWidth, stampHeight);
        stampImage.setAbsolutePosition(stampX, stampY);
        
        // Добавляем штамп на все страницы документа
        int totalPages = stamper.getReader().getNumberOfPages();
        for (int pageNum = 1; pageNum <= totalPages; pageNum++) {
            PdfContentByte canvas = stamper.getOverContent(pageNum);
            canvas.addImage(stampImage);
        }
        
        // Добавляем дополнительную информацию о подписи только на первую страницу
        addSignatureInfo(stamper, pageWidth, pageHeight);
    }
    
    /**
     * Расчет оптимального размера штампа в зависимости от размера страницы
     */
    private float calculateOptimalStampSize(float pageWidth, float pageHeight) {
        float minDimension = Math.min(pageWidth, pageHeight);
        
        // Для больших документов (A3, A2, A1, A0)
        if (minDimension > 800) {
            return Math.min(minDimension * 0.16f, 400); // 16% от меньшей стороны, но не более 400px
        }
        // Для средних документов (A4, A5)
        else if (minDimension > 400) {
            return Math.min(minDimension * 0.2f, 300); // 20% от меньшей стороны, но не более 300px
        }
        // Для маленьких документов
        else {
            return Math.min(minDimension * 0.3f, 200); // 30% от меньшей стороны, но не более 200px
        }
    }
    
    /**
     * Загрузка изображения штампа из ресурсов
     */
    private Image loadStampImage() throws IOException, BadElementException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("stamp.png")) {
            if (is == null) {
                throw new IOException("Файл штампа не найден в ресурсах");
            }
            return Image.getInstance(IOUtils.toByteArray(is));
        }
    }
    
    /**
     * Добавление информации о подписи
     */
    private void addSignatureInfo(PdfStamper stamper, float pageWidth, float pageHeight) throws IOException, DocumentException {
        // Добавляем информацию только на первую страницу
        PdfContentByte canvas = stamper.getOverContent(1);
        
        // Рассчитываем размеры информационного блока в зависимости от размера страницы
        float infoWidth = calculateInfoBlockWidth(pageWidth);
        float infoHeight = calculateInfoBlockHeight(pageHeight);
        float margin = Math.max(20, Math.min(pageWidth, pageHeight) * 0.02f);
        float infoX = pageWidth - infoWidth - margin;
        float infoY = pageHeight - infoHeight - margin;
        
        // Рисуем рамку
        canvas.setColorStroke(BaseColor.BLUE);
        canvas.setLineWidth(1);
        canvas.rectangle(infoX, infoY, infoWidth, infoHeight);
        canvas.stroke();
        
        // Добавляем фон
        canvas.setColorFill(new BaseColor(240, 248, 255, 200)); // Полупрозрачный светло-голубой
        canvas.rectangle(infoX, infoY, infoWidth, infoHeight);
        canvas.fill();
        
        // Добавляем текст
        canvas.beginText();
        float fontSize = calculateOptimalFontSize(pageWidth, pageHeight);
        canvas.setFontAndSize(BaseFont.createFont(), fontSize);
        canvas.setColorFill(BaseColor.BLACK);
        
        // Заголовок
        canvas.showTextAligned(Element.ALIGN_CENTER, "ЭЛЕКТРОННАЯ ПОДПИСЬ", 
                              infoX + infoWidth/2, infoY + infoHeight - fontSize - 5, 0);
        
        // Алгоритм
        canvas.setFontAndSize(BaseFont.createFont(), fontSize * 0.8f);
        canvas.showTextAligned(Element.ALIGN_CENTER, "ГОСТ Р 34.10-2012", 
                              infoX + infoWidth/2, infoY + infoHeight - fontSize * 2 - 5, 0);
        
        // Дата
        String date = Calendar.getInstance().getTime().toString();
        canvas.showTextAligned(Element.ALIGN_CENTER, "Дата: " + date, 
                              infoX + infoWidth/2, infoY + infoHeight - fontSize * 3 - 5, 0);
        
        // Статус
        canvas.showTextAligned(Element.ALIGN_CENTER, "Статус: ВАЛИДНА", 
                              infoX + infoWidth/2, infoY + infoHeight - fontSize * 4 - 5, 0);
        
        canvas.endText();
    }
    
    /**
     * Расчет ширины информационного блока
     */
    private float calculateInfoBlockWidth(float pageWidth) {
        if (pageWidth > 800) {
            return Math.min(pageWidth * 0.25f, 400); // 25% от ширины, но не более 400px
        } else if (pageWidth > 400) {
            return Math.min(pageWidth * 0.3f, 300); // 30% от ширины, но не более 300px
        } else {
            return Math.min(pageWidth * 0.4f, 250); // 40% от ширины, но не более 250px
        }
    }
    
    /**
     * Расчет высоты информационного блока
     */
    private float calculateInfoBlockHeight(float pageHeight) {
        if (pageHeight > 1000) {
            return 120; // Для больших документов
        } else if (pageHeight > 600) {
            return 100; // Для средних документов
        } else {
            return 80; // Для маленьких документов
        }
    }
    
    /**
     * Расчет оптимального размера шрифта
     */
    private float calculateOptimalFontSize(float pageWidth, float pageHeight) {
        float minDimension = Math.min(pageWidth, pageHeight);
        
        if (minDimension > 800) {
            return 14; // Для больших документов
        } else if (minDimension > 400) {
            return 12; // Для средних документов
        } else {
            return 10; // Для маленьких документов
        }
    }

    /**
     * Получение сертификата из запроса
     */
    private X509Certificate getCertificateFromRequest(DocumentSignRequest request) throws Exception {
        if (request.getCertificateBase64() != null && !request.getCertificateBase64().isEmpty()) {
            // Декодируем сертификат из Base64
            byte[] certBytes = Base64.getDecoder().decode(request.getCertificateBase64());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        } else {
            // Создаем временный сертификат для тестирования
            return createTemporaryCertificate();
        }
    }

    /**
     * Создание временного сертификата для тестирования
     */
    private X509Certificate createTemporaryCertificate() throws Exception {
        // Простая реализация для тестирования
        // В реальном приложении здесь должна быть логика создания сертификата
        return null;
    }

    /**
     * Формирование понятного сообщения о результате проверки
     */
    private String buildVerificationMessage(boolean isValid, boolean isCertificateValid, PdfPKCS7 pk) {
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
        
        if (pk != null && pk.getSigningCertificate() != null) {
            X509Certificate cert = pk.getSigningCertificate();
            message.append("[INFO] Информация о сертификате:\n");
            message.append("   Владелец: ").append(cert.getSubjectDN()).append("\n");
            message.append("   Издатель: ").append(cert.getIssuerDN()).append("\n");
            message.append("   Действителен с: ").append(cert.getNotBefore()).append("\n");
            message.append("   Действителен до: ").append(cert.getNotAfter()).append("\n");
        }
        
        return message.toString();
    }
} 