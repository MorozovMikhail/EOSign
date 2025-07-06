# Быстрый запуск проекта

## 🚀 Запуск за 5 минут

### 1. Проверьте требования
```bash
java -version    # Должен быть Java 8+
node --version   # Должен быть Node.js 14+
npm --version    # Должен быть npm 6+
mvn --version    # Должен быть Maven 3.6+
```

### 2. Запуск backend
```bash
# В корневой папке проекта
mvn clean install
mvn spring-boot:run
```

### 3. Запуск frontend (в новом терминале)
```bash
cd frontend2
npm install
npm start
```

### 4. Откройте браузер
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080

## 📋 Что делать дальше

1. **Создание подписи**: Загрузите PDF и нажмите "Подписать документ"
2. **Проверка подписи**: Загрузите PDF, signature.txt и сертификат
3. **Тестирование**: Используйте тестовые файлы из папки проекта

## ⚠️ Важные моменты

- Убедитесь, что порты 3000 и 8080 свободны
- Все JAR файлы JavaCSP должны быть в папках `java-csp-5.0.42119-A/` и `lib/`
- Для работы нужен файл `src/main/resources/stamp.png`

## 🔧 Если что-то не работает

### Backend не запускается
```bash
mvn clean
mvn install -U
```

### Frontend не запускается
```bash
cd frontend2
rm -rf node_modules package-lock.json
npm install
```

### Проблемы с портами
- Измените порт в `application.properties` (backend)
- Измените порт в `package.json` (frontend)

## 📞 Поддержка

См. полную документацию в `README.md` 