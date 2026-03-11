import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

export function SignIn() {
  const { signIn, isLoading } = useAuth();
  const [mode, setMode] = useState<'choose' | 'cyberbox'>('choose');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleCyberboxLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Preencha todos os campos.');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const text = await res.text();
        setError(text || 'Credenciais inválidas.');
        return;
      }
      window.location.reload();
    } catch {
      setError('Servidor indisponível. Tente novamente.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="si-page">
      {/* Left panel — brand on black */}
      <div className="si-left">
        {/* Matrix rain — falling logos */}
        <div className="si-matrix" aria-hidden="true">
          {Array.from({ length: 14 }, (_, col) => {
            const sizes = [12, 18, 28, 40, 22, 34, 16, 48, 24, 14, 36, 20, 44, 30];
            return (
              <div
                key={col}
                className="si-matrix-col"
                style={{
                  left: `${2 + col * 7}%`,
                  animationDuration: `${5 + (col % 4) * 3}s`,
                  animationDelay: `${-(col * 1.1)}s`,
                }}
              >
                {Array.from({ length: 10 }, (_, row) => {
                  const s = sizes[(col + row * 3) % sizes.length];
                  return (
                    <img
                      key={row}
                      src="/cyberboxlogo.png"
                      alt=""
                      className="si-matrix-logo"
                      style={{
                        width: `${s}px`,
                        height: `${s}px`,
                        opacity: 0.06 + (row % 5) * 0.03,
                        transform: `rotate(${-45 + ((col + row) * 37) % 90}deg)`,
                      }}
                    />
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className="si-brand">
          <img src="/cyberboxlogo.png" alt="Cyberbox" className="si-brand-logo" />
          <div className="si-brand-text">
            <span className="si-brand-name">CYBER<span className="si-brand-box">BOX</span></span>
            <span className="si-brand-siem">SIEM</span>
          </div>
        </div>
      </div>

      {/* Right panel — sign-in form */}
      <div className="si-right">
        <div className="si-form-wrap">
          <h1 className="si-title">
            {mode === 'cyberbox' ? 'Bem vindo de volta!' : 'Entrar na sua conta'}
          </h1>
          <p className="si-subtitle">
            {mode === 'cyberbox'
              ? 'Use o seu usuario e senha fornecidos pela CYBERBOX SECURITY para acessar a console.'
              : 'Selecione o método de autenticação para acessar o console.'}
          </p>

          {mode === 'choose' && (
            <>
              <button
                className="si-btn si-btn--ms"
                onClick={() => signIn()}
                disabled={isLoading}
              >
                <svg className="si-ms-icon" viewBox="0 0 21 21" fill="none">
                  <rect x="1" y="1" width="9" height="9" fill="#f25022" />
                  <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
                  <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
                  <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
                </svg>
                {isLoading ? 'Entrando...' : 'Entrar com Microsoft'}
              </button>

              <div className="si-or">
                <span className="si-or-line" />
                <span className="si-or-text">ou</span>
                <span className="si-or-line" />
              </div>

              <button
                className="si-btn si-btn--secondary"
                onClick={() => setMode('cyberbox')}
              >
                Cliente CYBERBOX?
              </button>
            </>
          )}

          {mode === 'cyberbox' && (
            <form className="si-form" onSubmit={handleCyberboxLogin}>
              <div className="si-field">
                <label className="si-label" htmlFor="si-email">E-mail</label>
                <input
                  id="si-email"
                  className="si-input"
                  type="email"
                  placeholder="seu@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoFocus
                />
              </div>
              <div className="si-field">
                <label className="si-label" htmlFor="si-password">Senha</label>
                <input
                  id="si-password"
                  className="si-input"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              {error && <p className="si-error">{error}</p>}

              <button
                className="si-btn si-btn--ms"
                type="submit"
                disabled={submitting}
              >
                {submitting ? 'Entrando...' : 'Entrar'}
              </button>

              <button
                type="button"
                className="si-back"
                onClick={() => { setMode('choose'); setError(''); }}
              >
                Voltar
              </button>
            </form>
          )}

          <div className="si-divider" />

          <p className="si-footer">
            Entre em contato com a CYBERBOX caso precise de acesso.
          </p>
        </div>
      </div>
    </div>
  );
}
