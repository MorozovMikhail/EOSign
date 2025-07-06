package ru.gostsign.service;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Service
public class TestPdfGenerator {
    
    /**
     * Генерирует простой тестовый PDF документ
     */
    public byte[] generateTestPdf() {
        try {
            Document document = new Document();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfWriter.getInstance(document, baos);
            
            document.open();
            
            // Добавляем заголовок
            Font titleFont = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD);
            Paragraph title = new Paragraph("Тестовый документ для подписания", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            document.add(title);
            
            document.add(new Paragraph(" ")); // Пустая строка
            
            // Добавляем содержимое
            Font normalFont = new Font(Font.FontFamily.HELVETICA, 12, Font.NORMAL);
            Paragraph content = new Paragraph();
            content.add(new Chunk("Это тестовый документ для проверки функциональности электронной подписи.\n\n", normalFont));
            content.add(new Chunk("Документ содержит:\n", normalFont));
            content.add(new Chunk("• Заголовок\n", normalFont));
            content.add(new Chunk("• Основной текст\n", normalFont));
            content.add(new Chunk("• Список элементов\n", normalFont));
            content.add(new Chunk("• Дату создания\n\n", normalFont));
            
            content.add(new Chunk("Дата создания: " + java.time.LocalDateTime.now().toString() + "\n", normalFont));
            content.add(new Chunk("Статус: Готов к подписанию\n", normalFont));
            
            document.add(content);
            
            document.close();
            return baos.toByteArray();
            
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при создании тестового PDF: " + e.getMessage(), e);
        }
    }
} 