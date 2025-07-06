import React, { useState } from 'react';
import './App.css';
import logo from './logo.png';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

// Типы для разных режимов
type Mode = 'create' | 'sign' | 'verify';

// Интерфейсы для форм
interface CreateSignatureForm {
  surname: string;
  givenName: string;
  title: string;
  organizationName: string;
  city: string;
  address: string;
  email: string;
  inn: string;
  ogrn: string;
}

interface SignDocumentForm {
  privateKeyFile: File | null;
  certificateFile: File | null;
  documentFile: File | null;
  // Поля для динамических данных штампа
  stampOrganizationName: string;
  stampDirector: string;
  stampInn: string;
  stampValidityPeriod: string;
}

interface VerifySignatureForm {
  certificateFile: File | null;
  signatureFile: File | null;
  documentFile: File | null;
}

// Начальные состояния
const initialCreateForm: CreateSignatureForm = {
  surname: '',
  givenName: '',
  title: '',
  organizationName: '',
  city: '',
  address: '',
  email: '',
  inn: '',
  ogrn: '',
};

const initialSignForm: SignDocumentForm = {
  privateKeyFile: null,
  certificateFile: null,
  documentFile: null,
  stampOrganizationName: '',
  stampDirector: '',
  stampInn: '',
  stampValidityPeriod: '',
};

const initialVerifyForm: VerifySignatureForm = {
  certificateFile: null,
  signatureFile: null,
  documentFile: null,
};

// Плейсхолдеры и лейблы
const placeholders = {
  surname: 'Иванов',
  givenName: 'Иван Иванович',
  title: 'Директор',
  organizationName: 'ООО "Ромашка"',
  city: 'Москва',
  address: 'ул. Ленина, д. 1',
  email: 'ivanov@example.com',
  inn: '1234567890',
  ogrn: '1234567890123',
};

const labels = {
  surname: 'Фамилия',
  givenName: 'Имя и отчество',
  title: 'Должность',
  organizationName: 'Организация',
  city: 'Город',
  address: 'Адрес (без города)',
  email: 'Электронная почта',
  inn: 'ИНН',
  ogrn: 'ОГРН',
};

const emailPattern = /^[\w.-]+@[\w.-]+\.[A-Za-z]{2,}$/;

function App() {
  const [mode, setMode] = useState<Mode>('create');
  const [createForm, setCreateForm] = useState<CreateSignatureForm>(initialCreateForm);
  const [signForm, setSignForm] = useState<SignDocumentForm>(initialSignForm);
  const [verifyForm, setVerifyForm] = useState<VerifySignatureForm>(initialVerifyForm);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [fieldErrors, setFieldErrors] = useState<any>({});

  // Валидация формы создания подписи
  const validateCreateForm = () => {
    const errors: any = {};
    if (!emailPattern.test(createForm.email)) {
      errors.email = 'Некорректный email';
    }
    return errors;
  };

  // Обработчики изменений для формы создания подписи
  const handleCreateFormChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    let newValue = value;
    if (name === 'inn') {
      newValue = newValue.replace(/\D/g, '').slice(0, 12);
    }
    if (name === 'ogrn') {
      newValue = newValue.replace(/\D/g, '').slice(0, 15);
    }
    setCreateForm({ ...createForm, [name]: newValue });
    setFieldErrors({ ...fieldErrors, [name]: undefined });
  };

  // Обработчики файлов для подписания документа
  const handleSignFileChange = (field: keyof SignDocumentForm) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setSignForm({ ...signForm, [field]: file });
  };

  // Обработчики файлов для проверки подписи
  const handleVerifyFileChange = (field: keyof VerifySignatureForm) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setVerifyForm({ ...verifyForm, [field]: file });
  };

  // Обработчики изменений для полей штампа
  const handleStampFieldChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    let newValue = value;
    if (name === 'stampInn') {
      newValue = newValue.replace(/\D/g, '').slice(0, 12);
    }
    setSignForm({ ...signForm, [name]: newValue });
  };

  // Создание подписи
  const handleCreateSignature = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    const errors = validateCreateForm();
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    
    setLoading(true);
    try {
      const response = await fetch('/api/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(createForm),
      });
      if (!response.ok) throw new Error('Ошибка при генерации подписи');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'signature.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setSuccess('Подпись успешно сгенерирована и скачана!');
    } catch (e: any) {
      setError(e.message || 'Неизвестная ошибка');
    } finally {
      setLoading(false);
    }
  };

  // Подписание документа
  const handleSignDocument = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    if (!signForm.privateKeyFile || !signForm.certificateFile || !signForm.documentFile) {
      setError('Пожалуйста, выберите файлы приватного ключа, сертификата и документа');
      return;
    }
    
    setLoading(true);
    try {
      const privateKeyBase64 = await fileToBase64(signForm.privateKeyFile);
      const certificateBase64 = await fileToBase64(signForm.certificateFile);
      const documentBytes = await fileToBytes(signForm.documentFile);
      
      const response = await fetch('/api/sign-document-with-signature', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          privateKeyBase64,
          certificateBase64,
          documentBytes: Array.from(documentBytes),
          // Данные для штампа
          stampOrganizationName: signForm.stampOrganizationName,
          stampDirector: signForm.stampDirector,
          stampInn: signForm.stampInn,
          stampValidityPeriod: signForm.stampValidityPeriod
        }),
      });
      
      if (response.ok) {
        const blob = await response.blob();
        // Сохраняем ZIP архив
        saveAs(blob, 'signed_document_with_signature.zip');
        setSuccess('Документ успешно подписан!');
      } else {
        setError('Ошибка при подписании документа');
      }
    } catch (err) {
      setError('Ошибка при подписании: ' + err);
    } finally {
      setLoading(false);
    }
  };

  // Проверка подписи
  const handleVerifySignature = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!verifyForm.documentFile || !verifyForm.signatureFile || !verifyForm.certificateFile) {
      setError('Пожалуйста, выберите все три файла для проверки подписи.');
      return;
    }

    setLoading(true);
    try {
      const documentBytes = await fileToBytes(verifyForm.documentFile);
      const signatureBase64 = await fileToText(verifyForm.signatureFile);
      const certificateBase64 = await fileToBase64(verifyForm.certificateFile);

      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          documentBytes: Array.from(documentBytes),
          signatureBase64,
          certificateBase64
        }),
      });

      if (!response.ok) throw new Error('Ошибка при проверке подписи');

      const result = await response.json();
      setSuccess(result.message);
    } catch (e: any) {
      setError(e.message || 'Неизвестная ошибка');
    } finally {
      setLoading(false);
    }
  };

  // Утилиты для работы с файлами
  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => {
        const result = reader.result as string;
        resolve(result.split(',')[1]); // Убираем префикс data:application/octet-stream;base64,
      };
      reader.onerror = error => reject(error);
    });
  };

  const fileToBytes = (file: File): Promise<Uint8Array> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsArrayBuffer(file);
      reader.onload = () => {
        const result = reader.result as ArrayBuffer;
        resolve(new Uint8Array(result));
      };
      reader.onerror = error => reject(error);
    });
  };

  // Добавь утилиту для чтения файла как текста
  const fileToText = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsText(file);
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = error => reject(error);
    });
  };

  return (
    <div className="App">
      <header className="header">
        <img src={logo} alt="EOSign" className="logo-uncompressed" />
        <span className="brand">EOSign</span>
      </header>
      
      <div className="mode-selector">
        <button 
          className={`mode-button ${mode === 'create' ? 'active' : ''}`}
          onClick={() => setMode('create')}
        >
          Создать подпись
        </button>
        <button 
          className={`mode-button ${mode === 'sign' ? 'active' : ''}`}
          onClick={() => setMode('sign')}
        >
          Подписать документ
        </button>
        <button 
          className={`mode-button ${mode === 'verify' ? 'active' : ''}`}
          onClick={() => setMode('verify')}
        >
          Проверить подпись
        </button>
      </div>

      <div className="content">
        {mode === 'create' && (
          <form className="form-card" onSubmit={handleCreateSignature} autoComplete="off">
            <h2>Создание неквалифицированной подписи</h2>
            {Object.keys(labels).map((key) => (
              <div className="input-row" key={key}>
                <label htmlFor={key}>{labels[key as keyof typeof labels]} *</label>
                <input
                  id={key}
                  name={key}
                  placeholder={placeholders[key as keyof typeof placeholders]}
                  value={createForm[key as keyof typeof createForm]}
                  onChange={handleCreateFormChange}
                  required
                  type={key === 'email' ? 'email' : 'text'}
                  autoComplete="off"
                />
                {fieldErrors[key] && <div className="field-error">{fieldErrors[key]}</div>}
              </div>
            ))}
            <button type="submit" disabled={loading}>
              {loading ? 'Генерация...' : 'СГЕНЕРИРОВАТЬ ПОДПИСЬ'}
            </button>
          </form>
        )}

        {mode === 'sign' && (
          <form className="form-card" onSubmit={handleSignDocument}>
            <h2>Подписание документа</h2>
            <div className="input-row">
              <label htmlFor="privateKey">Приватный ключ (.der файл) *</label>
              <input
                id="privateKey"
                type="file"
                accept=".der"
                onChange={handleSignFileChange('privateKeyFile')}
                required
              />
            </div>
            <div className="input-row">
              <label htmlFor="certificate">Сертификат (.cer файл) *</label>
              <input
                id="certificate"
                type="file"
                accept=".cer"
                onChange={handleSignFileChange('certificateFile')}
                required
              />
            </div>
            <div className="input-row">
              <label htmlFor="document">Документ для подписания (PDF) *</label>
              <input
                id="document"
                type="file"
                accept=".pdf"
                onChange={handleSignFileChange('documentFile')}
                required
              />
            </div>
            
            <div className="stamp-section">
              <h3>Данные для штампа (необязательно)</h3>
              <div className="input-row">
                <label htmlFor="stampOrganizationName">Название организации</label>
                <input
                  id="stampOrganizationName"
                  name="stampOrganizationName"
                  type="text"
                  placeholder="ООО 'Ромашка'"
                  value={signForm.stampOrganizationName}
                  onChange={handleStampFieldChange}
                />
              </div>
              <div className="input-row">
                <label htmlFor="stampDirector">Директор</label>
                <input
                  id="stampDirector"
                  name="stampDirector"
                  type="text"
                  placeholder="Иванов И.И."
                  value={signForm.stampDirector}
                  onChange={handleStampFieldChange}
                />
              </div>
              <div className="input-row">
                <label htmlFor="stampInn">ИНН</label>
                <input
                  id="stampInn"
                  name="stampInn"
                  type="text"
                  placeholder="1234567890"
                  value={signForm.stampInn}
                  onChange={handleStampFieldChange}
                />
              </div>
              <div className="input-row">
                <label htmlFor="stampValidityPeriod">Срок действия</label>
                <input
                  id="stampValidityPeriod"
                  name="stampValidityPeriod"
                  type="text"
                  placeholder="01.01.2024 - 31.12.2024"
                  value={signForm.stampValidityPeriod}
                  onChange={handleStampFieldChange}
                />
              </div>
            </div>
            
            <button type="submit" disabled={loading}>
              {loading ? 'Подписание...' : 'ПОДПИСАТЬ ДОКУМЕНТ'}
            </button>
          </form>
        )}

        {mode === 'verify' && (
          <form className="form-card" onSubmit={handleVerifySignature}>
            <h2>Проверка подписи</h2>
            <div className="input-row">
              <label htmlFor="verifyDocument">Подписанный документ (PDF) *</label>
              <input
                id="verifyDocument"
                type="file"
                accept=".pdf"
                onChange={handleVerifyFileChange('documentFile')}
                required
              />
            </div>
            <div className="input-row">
              <label htmlFor="verifySignature">Файл подписи (signature.txt) *</label>
              <input
                id="verifySignature"
                type="file"
                accept=".txt,.sig,.bin"
                onChange={handleVerifyFileChange('signatureFile')}
                required
              />
            </div>
            <div className="input-row">
              <label htmlFor="verifyCertificate">Сертификат (.cer) *</label>
              <input
                id="verifyCertificate"
                type="file"
                accept=".cer"
                onChange={handleVerifyFileChange('certificateFile')}
                required
              />
            </div>
            <div className="info-box">
              <p><strong>Инструкция:</strong></p>
              <ul>
                <li>Загрузите PDF с уже добавленным штампом</li>
                <li>Загрузите файл подписи (обычно signature.txt)</li>
                <li>Загрузите сертификат (.cer)</li>
                <li>Все три файла обязательны для проверки</li>
              </ul>
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Проверка...' : 'ПРОВЕРИТЬ ПОДПИСЬ'}
            </button>
          </form>
        )}

        {error && <div className="error">{error}</div>}
        {success && <div className="success">{success}</div>}
      </div>
    </div>
  );
}

export default App;
