import React, { Component, ErrorInfo, ReactNode } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[DEEPSHEILD SYSTEM CRASH CAPTURED]:', error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          backgroundColor: '#070b14',
          color: '#f8fafc',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px',
          fontFamily: 'monospace'
        }}>
          <div style={{
            maxWidth: '650px',
            width: '100%',
            backgroundColor: 'rgba(225, 29, 72, 0.1)',
            border: '2px solid #e11d48',
            borderRadius: '16px',
            padding: '24px',
            boxShadow: '0 0 40px rgba(225, 29, 72, 0.3)'
          }}>
            <h2 style={{ color: '#f43f5e', fontSize: '18px', fontWeight: 'bold', marginBottom: '8px' }}>
              ⚠️ DEEPSHEILD RUNTIME EXCEPTION INTERCEPTED
            </h2>
            <p style={{ color: '#cbd5e1', fontSize: '13px', marginBottom: '16px' }}>
              The application encountered a client-side execution error. Zero-Trust watchdog prevented silent failure.
            </p>
            <div style={{
              backgroundColor: '#050811',
              padding: '12px',
              borderRadius: '8px',
              color: '#fb7185',
              fontSize: '12px',
              marginBottom: '16px',
              overflowX: 'auto'
            }}>
              <strong>Error:</strong> {this.state.error?.message || 'Unknown runtime error'}
            </div>
            <button
              onClick={() => window.location.reload()}
              style={{
                backgroundColor: '#e11d48',
                color: '#fff',
                border: 'none',
                padding: '10px 20px',
                borderRadius: '8px',
                fontWeight: 'bold',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              RELOAD DASHBOARD
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
