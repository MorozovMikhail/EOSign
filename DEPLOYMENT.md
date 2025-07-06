# Руководство по развертыванию

## 🖥️ Подготовка нового ПК

### 1. Установка необходимого ПО

#### Java Development Kit (JDK)
```bash
# Скачайте и установите JDK 8 или выше
# https://www.oracle.com/java/technologies/downloads/
# или OpenJDK: https://adoptium.net/

# Проверка установки
java -version
javac -version
```

#### Node.js и npm
```bash
# Скачайте и установите Node.js 14+ с официального сайта
# https://nodejs.org/

# Проверка установки
node --version
npm --version
```

#### Maven
```bash
# Скачайте Maven 3.6+ с официального сайта
# https://maven.apache.org/download.cgi

# Или используйте пакетный менеджер:
# Windows: choco install maven
# macOS: brew install maven
# Ubuntu: sudo apt install maven

# Проверка установки
mvn --version
```

### 2. Клонирование проекта

```bash
# Клонируйте репозиторий
git clone https://github.com/MorozovMikhail/EOSign.git
cd EOSign

# Проверьте, что все файлы на месте
ls -la
```

## 🚀 Первый запуск

### 1. Проверка структуры проекта

Убедитесь, что у вас есть следующие папки и файлы:
```
EOSign/
├── src/                          # Backend код
├── frontend2/                    # Frontend код
├── java-csp-5.0.42119-A/        # Библиотеки JavaCSP
├── lib/                         # Дополнительные JAR
├── pom.xml                      # Maven конфигурация
├── README.md                    # Документация
└── QUICK_START.md              # Быстрый старт
```

### 2. Запуск backend

```bash
# В корневой папке проекта
mvn clean install

# Если возникают ошибки с зависимостями:
mvn clean install -U

# Запуск приложения
mvn spring-boot:run
```

**Ожидаемый результат**: В консоли должно появиться сообщение о запуске Spring Boot на порту 8080.

### 3. Запуск frontend

```bash
# Откройте новый терминал
cd frontend2

# Установка зависимостей
npm install

# Запуск приложения
npm start
```

**Ожидаемый результат**: Браузер должен автоматически открыться на http://localhost:3000

## 🔧 Настройка окружения

### Переменные окружения (опционально)

Создайте файл `.env` в корне проекта:
```bash
# Backend настройки
SERVER_PORT=8080
SPRING_PROFILES_ACTIVE=dev

# Frontend настройки
REACT_APP_API_URL=http://localhost:8080
```

### Настройка портов

Если порты 3000 или 8080 заняты:

#### Backend (application.properties)
```properties
server.port=8081
```

#### Frontend (package.json)
```json
{
  "scripts": {
    "start": "set PORT=3001 && react-scripts start"
  }
}
```

## 📋 Проверка работоспособности

### 1. Тест backend API

```bash
# Проверка доступности сервера
curl http://localhost:8080/actuator/health

# Или откройте в браузере:
# http://localhost:8080/actuator/health
```

### 2. Тест frontend

1. Откройте http://localhost:3000
2. Убедитесь, что интерфейс загружается
3. Проверьте, что нет ошибок в консоли браузера (F12)

### 3. Тест функциональности

1. **Создание подписи**:
   - Загрузите любой PDF файл
   - Нажмите "Подписать документ"
   - Должен скачаться ZIP-архив

2. **Проверка подписи**:
   - Используйте файлы из скачанного архива
   - Загрузите PDF, signature.txt и сертификат
   - Нажмите "Проверить подпись"

## 🐛 Устранение проблем

### Проблемы с Java

```bash
# Проверка версии Java
java -version

# Если Java не найдена, добавьте в PATH:
# Windows: C:\Program Files\Java\jdk-версия\bin
# Linux/macOS: export JAVA_HOME=/path/to/java
```

### Проблемы с Maven

```bash
# Очистка кэша Maven
mvn clean

# Принудительное обновление зависимостей
mvn clean install -U

# Проверка локального репозитория
rm -rf ~/.m2/repository
mvn clean install
```

### Проблемы с npm

```bash
# Очистка кэша npm
npm cache clean --force

# Удаление node_modules и переустановка
rm -rf node_modules package-lock.json
npm install

# Проверка версии Node.js
node --version
```

### Проблемы с портами

```bash
# Windows - проверка занятых портов
netstat -ano | findstr :8080
netstat -ano | findstr :3000

# Linux/macOS - проверка занятых портов
lsof -i :8080
lsof -i :3000

# Завершение процесса по PID
# Windows: taskkill /PID номер_процесса /F
# Linux/macOS: kill -9 номер_процесса
```

### Проблемы с JavaCSP

Убедитесь, что все JAR файлы присутствуют:
```bash
# Проверка наличия файлов
ls java-csp-5.0.42119-A/*.jar
ls lib/*.jar

# Если файлы отсутствуют, скачайте их заново
```

## 📦 Сборка для продакшена

### Backend JAR
```bash
mvn clean package -DskipTests
# JAR файл будет в target/untitled-1.0-SNAPSHOT.jar
```

### Frontend build
```bash
cd frontend2
npm run build
# Собранные файлы будут в build/
```

## 🔒 Безопасность

### Рекомендации для продакшена

1. **Изменение портов по умолчанию**
2. **Настройка HTTPS**
3. **Ограничение CORS**
4. **Логирование**
5. **Мониторинг**

### Файлы конфигурации

```properties
# application-prod.properties
server.port=8443
server.ssl.enabled=true
logging.level.ru.gostsign=INFO
```

## 📞 Поддержка

При возникновении проблем:

1. Проверьте логи в консоли
2. Убедитесь в корректности версий ПО
3. Проверьте наличие всех файлов проекта
4. Обратитесь к документации в README.md

## ✅ Чек-лист готовности

- [ ] Java 8+ установлена
- [ ] Node.js 14+ установлен
- [ ] Maven 3.6+ установлен
- [ ] Проект склонирован
- [ ] Backend запускается без ошибок
- [ ] Frontend запускается без ошибок
- [ ] API доступен по http://localhost:8080
- [ ] Frontend доступен по http://localhost:3000
- [ ] Создание подписи работает
- [ ] Проверка подписи работает

**Проект готов к использованию!** 🎉 