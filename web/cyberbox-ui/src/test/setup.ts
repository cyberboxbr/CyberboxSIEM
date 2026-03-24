import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

if (!('scrollIntoView' in HTMLElement.prototype)) {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
    configurable: true,
    value: vi.fn(),
  });
}

if (!window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

if (!window.requestAnimationFrame) {
  window.requestAnimationFrame = (callback) =>
    window.setTimeout(() => callback(performance.now()), 16);
}

if (!window.cancelAnimationFrame) {
  window.cancelAnimationFrame = (handle) => window.clearTimeout(handle);
}
