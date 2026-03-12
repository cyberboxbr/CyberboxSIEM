import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '64px 32px', textAlign: 'center', color: '#94a3b8' }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>&#x26A0;</div>
          <h2 style={{ color: '#e2e8f0', fontSize: 20, marginBottom: 8 }}>Something went wrong</h2>
          <p style={{ fontSize: 14, marginBottom: 16, maxWidth: 500, margin: '0 auto 16px' }}>
            {this.state.error?.message ?? 'An unexpected error occurred.'}
          </p>
          <button
            type="button"
            onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }}
            style={{
              background: '#334155',
              color: '#e2e8f0',
              border: '1px solid #475569',
              borderRadius: 6,
              padding: '8px 20px',
              cursor: 'pointer',
              fontSize: 14,
            }}
          >
            Reload page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
