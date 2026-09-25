import React from 'react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex-1 p-8 bg-rose-950 text-white overflow-y-auto">
          <h2 className="text-2xl font-bold mb-4">React Error Boundary</h2>
          <div className="bg-black/50 p-4 rounded font-mono text-sm whitespace-pre-wrap">
            <span className="text-rose-400 font-bold">{this.state.error && this.state.error.toString()}</span>
            <br />
            <span className="text-slate-400">{this.state.errorInfo && this.state.errorInfo.componentStack}</span>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
