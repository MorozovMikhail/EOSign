package ru.gostsign.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.gostsign.model.SignRequest;
import ru.gostsign.service.GostSignService;

@RestController
@RequestMapping("/api/sign")
@RequiredArgsConstructor
public class SignController {
    private final GostSignService gostSignService;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> sign(@RequestBody SignRequest request) {
        byte[] zipBytes = gostSignService.generateAndSign(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signature.zip")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(zipBytes);
    }
} 