import React, { useState } from 'react';
import { Crosshair, Lock, User, AlertCircle, Loader2 } from 'lucide-react';
import { loginOperator } from '../services/api';

export default function LoginScreen({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setIsLoading(true);
    setErrorMsg(null);

    try {
      const res = await loginOperator(username.trim(), password);
      onLoginSuccess(res);
    } catch (err) {
      setErrorMsg(err.message || 'Invalid username or password');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen bg-[#090b10] text-slate-100 flex flex-col items-center justify-center p-4 font-mono select-text">
      <div className="w-full max-w-sm bg-[#0c1017] border border-[#1e2638] rounded-md overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="px-6 py-5 bg-[#0f141e] border-b border-[#1e2638] flex items-center space-x-3.5">
          <div className="w-9 h-9 bg-[#0f172a] border border-[#38bdf8]/40 rounded flex items-center justify-center text-[#38bdf8] shrink-0">
            <Crosshair size={20} />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-white">SNIPERSCOPE</h1>
            <p className="text-[11px] text-slate-400 mt-0.5">Sign in to your account</p>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMsg && (
            <div className="p-2.5 bg-[#2a1317] border border-[#7f1d1d] rounded text-xs text-[#f87171] flex items-center space-x-2">
              <AlertCircle size={14} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs text-slate-400">Username</label>
            <div className="relative flex items-center">
              <User size={14} className="absolute left-3 text-slate-500" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                required
                autoComplete="username"
                className="w-full bg-[#07090e] border border-[#1e2638] focus:border-[#38bdf8] focus:outline-none text-sm text-white pl-9 pr-3 py-2 rounded transition-colors"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs text-slate-400">Password</label>
            <div className="relative flex items-center">
              <Lock size={14} className="absolute left-3 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                required
                autoComplete="current-password"
                className="w-full bg-[#07090e] border border-[#1e2638] focus:border-[#38bdf8] focus:outline-none text-sm text-white pl-9 pr-3 py-2 rounded transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading || !username.trim() || !password}
            className="w-full py-2 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-40 text-white text-xs font-bold uppercase tracking-wider rounded transition-colors flex items-center justify-center space-x-2 cursor-pointer mt-2"
          >
            {isLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                <span>Signing in...</span>
              </>
            ) : (
              <span>Sign in</span>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
