// Small line charts over one run series. HistoryChart draws coverage and distinct per run;
// Panel, Frame, Tip and useWidth are shared with the status page's cost chart.
// One series per panel, 2px line, 8px markers with a surface ring, a crosshair tooltip on hover.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import styled from 'styled-components';
import { variables } from '@splunk/themes';
import { dateTime, num, pct, slot } from '../lib/format';
import { Muted } from './styles';

export const Frame = styled.div`
    position: relative;
    width: 100%;
`;

const Svg = styled.svg`
    display: block;
    width: 100%;
    height: ${(props) => props.height}px;
    .grid {
        stroke: ${variables.borderColorWeak};
        stroke-width: 1;
    }
    .axis {
        fill: ${variables.contentColorMuted};
        font-size: 11px;
    }
    .line {
        fill: none;
        stroke: ${variables.interactiveColorPrimary};
        stroke-width: 2;
        stroke-linejoin: round;
        stroke-linecap: round;
    }
    .dot {
        fill: ${variables.interactiveColorPrimary};
        stroke: ${variables.backgroundColorSection};
        stroke-width: 2;
    }
    .hair {
        stroke: ${variables.contentColorMuted};
        stroke-width: 1;
    }
    .title {
        fill: ${variables.contentColorDefault};
        font-size: 12px;
        font-weight: 600;
    }
`;

export const Tip = styled.div`
    position: absolute;
    top: 4px;
    pointer-events: none;
    background: ${variables.backgroundColorSection};
    border: 1px solid ${variables.borderColor};
    padding: 4px 8px;
    font-size: 12px;
    white-space: nowrap;
    b {
        font-weight: 600;
    }
`;

export const PAD = { left: 48, right: 16, top: 20, bottom: 18 };

export function useWidth(ref) {
    const [width, setWidth] = useState(800);
    useEffect(() => {
        if (!ref.current) return undefined;
        const measure = () => setWidth(ref.current ? ref.current.clientWidth : 800);
        measure();
        const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(measure) : null;
        if (observer) observer.observe(ref.current);
        window.addEventListener('resize', measure);
        return () => {
            if (observer) observer.disconnect();
            window.removeEventListener('resize', measure);
        };
    }, [ref]);
    return width;
}

function ticks(max, count) {
    if (max <= 0) return [0];
    const raw = max / count;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag;
    const out = [];
    for (let v = 0; v <= max + step * 0.001; v += step) out.push(v);
    return out;
}

export function Panel({ title, points, valueOf, format, max, width, height, hover, onHover }) {
    const inner = width - PAD.left - PAD.right;
    const plotH = height - PAD.top - PAD.bottom;
    const times = points.map((p) => p.time);
    const t0 = Math.min(...times);
    const t1 = Math.max(...times);
    const x = (t) => PAD.left + (t1 === t0 ? inner / 2 : ((t - t0) / (t1 - t0)) * inner);
    const y = (v) => PAD.top + plotH - (max === 0 ? 0 : (v / max) * plotH);
    const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.time).toFixed(1)},${y(valueOf(p)).toFixed(1)}`).join(' ');
    const yTicks = ticks(max, 3);
    const move = (event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        const px = event.clientX - rect.left;
        let best = 0;
        points.forEach((p, i) => {
            if (Math.abs(x(p.time) - px) < Math.abs(x(points[best].time) - px)) best = i;
        });
        onHover(best);
    };
    return (
        <Svg height={height} onMouseMove={move} onMouseLeave={() => onHover(null)} role="img" aria-label={title}>
            <text className="title" x={PAD.left} y={13}>
                {title}
            </text>
            {yTicks.map((v) => (
                <g key={v}>
                    <line className="grid" x1={PAD.left} x2={width - PAD.right} y1={y(v)} y2={y(v)} />
                    <text className="axis" x={PAD.left - 6} y={y(v) + 4} textAnchor="end">
                        {format(v)}
                    </text>
                </g>
            ))}
            <text className="axis" x={PAD.left} y={height - 4}>
                {dateTime(t0)}
            </text>
            <text className="axis" x={width - PAD.right} y={height - 4} textAnchor="end">
                {dateTime(t1)}
            </text>
            {hover !== null && points[hover] ? (
                <line className="hair" x1={x(points[hover].time)} x2={x(points[hover].time)} y1={PAD.top} y2={PAD.top + plotH} />
            ) : null}
            <path className="line" d={path} />
            {points.map((p, i) => (
                <circle key={p.runId + (p.mode || '')} className="dot" cx={x(p.time)} cy={y(valueOf(p))} r={hover === i ? 5 : 4} />
            ))}
        </Svg>
    );
}

export default function HistoryChart({ points }) {
    const ref = useRef(null);
    const width = useWidth(ref);
    const [hover, setHover] = useState(null);
    const sorted = useMemo(() => [...points].sort((a, b) => a.time - b.time), [points]);
    if (!sorted.length) return <Muted>no committed rows in the window</Muted>;
    const maxDistinct = Math.max(1, ...sorted.map((p) => p.distinct));
    const p = hover !== null ? sorted[hover] : null;
    return (
        <Frame ref={ref}>
            <Panel
                title="coverage"
                points={sorted}
                valueOf={(d) => d.coverage}
                format={(v) => pct(v)}
                max={1}
                width={width}
                height={120}
                hover={hover}
                onHover={setHover}
            />
            <Panel
                title="distinct"
                points={sorted}
                valueOf={(d) => d.distinct}
                format={(v) => num(v)}
                max={maxDistinct}
                width={width}
                height={120}
                hover={hover}
                onHover={setHover}
            />
            {p ? (
                <Tip style={{ left: Math.min(width - 260, Math.max(0, PAD.left + 8)) }}>
                    <b>{pct(p.coverage)}</b> coverage, <b>{num(p.distinct)}</b> distinct, <b>{num(p.count)}</b> of{' '}
                    <b>{num(p.events)}</b> events; run {slot(p.runId)}, {p.mode}
                </Tip>
            ) : null}
        </Frame>
    );
}
