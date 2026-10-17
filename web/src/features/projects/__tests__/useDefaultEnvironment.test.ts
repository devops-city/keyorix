import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import type { ProjectEnvironment } from '../../../services/projects';
import { pickDefaultEnvironment, useDefaultEnvironment } from '../useDefaultEnvironment';

const withCounts = (counts: (number | undefined)[]): ProjectEnvironment[] =>
    ['development', 'staging', 'production'].map((name, i) => ({
        id: i + 1,
        name,
        projectId: 9,
        secretCount: counts[i],
    }));

describe('pickDefaultEnvironment', () => {
    it('keeps production when production has secrets', () => {
        expect(pickDefaultEnvironment(withCounts([1, 0, 4]))).toBe('production');
    });

    it('lands on the environment that has the secrets when production is empty (DEMO-WALK-3 #6/#36)', () => {
        expect(pickDefaultEnvironment(withCounts([1, 0, 0]))).toBe('development');
        expect(pickDefaultEnvironment(withCounts([0, 2, 0]))).toBe('staging');
    });

    it('falls back to production when nothing has secrets or the server sent no counts', () => {
        expect(pickDefaultEnvironment(withCounts([0, 0, 0]))).toBe('production');
        expect(pickDefaultEnvironment(withCounts([undefined, undefined, undefined]))).toBe('production');
    });

    it('falls back to the first environment when there is no production', () => {
        expect(pickDefaultEnvironment(withCounts([0, 0, 0]).slice(0, 2))).toBe('development');
        expect(pickDefaultEnvironment([])).toBe('production');
    });
});

describe('useDefaultEnvironment', () => {
    it('is undecided (null) until the environment list has loaded', () => {
        const { result } = renderHook(() => useDefaultEnvironment([], true));
        expect(result.current.name).toBeNull();
    });

    it('picks the environment with the secret straight from the list, with no further request', () => {
        const { result } = renderHook(() => useDefaultEnvironment(withCounts([1, 0, 0]), true));
        expect(result.current.name).toBe('development');
    });

    it('keeps production when the URL already names an environment', () => {
        const { result } = renderHook(() => useDefaultEnvironment(withCounts([1, 0, 0]), false));
        expect(result.current.name).toBe('production');
    });
});
