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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

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
                zip.putArchiveEntry(new ZipArchiveEntry("private_key.der"));
                zip.write(keyPair.getPrivate().getEncoded());
                zip.closeArchiveEntry();
            }
            return baos.toByteArray();
        } catch (GeneralSecurityException | IOException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new RuntimeException("Ошибка при генерации подписи: " + e.getMessage(), e);
        }
    }
} 