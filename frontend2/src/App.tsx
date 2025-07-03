import React, { useState } from 'react';
import './App.css';
import logo from './logo.png';

const initialState = {
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

const emailPattern = /^[\w.-]+@[\w.-]+\.[A-Za-z]{2,}$/;

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

function App() {
  const [form, setForm] = useState(initialState);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<any>({});

  const validate = () => {
    const errors: any = {};
    if (!emailPattern.test(form.email)) {
      errors.email = 'Некорректный email';
    }
    return errors;
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    let newValue = value;
    if (name === 'inn') {
      newValue = newValue.replace(/\D/g, '').slice(0, 12);
    }
    if (name === 'ogrn') {
      newValue = newValue.replace(/\D/g, '').slice(0, 15);
    }
    setForm({ ...form, [name]: newValue });
    setFieldErrors({ ...fieldErrors, [name]: undefined });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess(false);
    const errors = validate();
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    setLoading(true);
    try {
      const response = await fetch('/api/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
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
      setSuccess(true);
    } catch (e: any) {
      setError(e.message || 'Неизвестная ошибка');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="header">
        <img src={logo} alt="EOSign" className="logo-uncompressed" />
        <span className="brand">EOSign</span>
      </header>
      <form className="form-card" onSubmit={handleSubmit} autoComplete="off">
        <h2>Создание неквалифицированной подписи</h2>
        {Object.keys(labels).map((key) => (
          <div className="input-row" key={key}>
            <label htmlFor={key}>{labels[key as keyof typeof labels]} *</label>
            <input
              id={key}
              name={key}
              placeholder={placeholders[key as keyof typeof placeholders]}
              value={form[key as keyof typeof form]}
              onChange={handleChange}
              required
              type={key === 'email' ? 'email' : 'text'}
              autoComplete="off"
            />
            {fieldErrors[key] && <div className="field-error">{fieldErrors[key]}</div>}
          </div>
        ))}
        <button type="submit" disabled={loading}>{loading ? 'Генерация...' : 'СГЕНЕРИРОВАТЬ ПОДПИСЬ'}</button>
        {error && <div className="error">{error}</div>}
        {success && <div className="success">Подпись успешно сгенерирована и скачана!</div>}
      </form>
    </div>
  );
}

export default App;
