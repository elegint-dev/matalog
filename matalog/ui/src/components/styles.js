// Dense page furniture shared by every page: wrappers, muted text, inline bars, mono text.
import React from 'react';
import styled from 'styled-components';
import { variables } from '@splunk/themes';

export const Muted = styled.span`
    color: ${variables.contentColorMuted};
    font-size: 12px;
`;

export const Mono = styled.span`
    font-family: ${variables.monoFontFamily};
    font-size: 12px;
    word-break: break-all;
`;

// Table cells lay their content out as a flex row, so small text inherits the cell line height to share its baseline.
export const Wrap = styled.div`
    max-width: 1280px;
    margin: 0 auto;
    padding: 16px 24px 48px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    color: ${variables.contentColorDefault};
    font-size: 13px;
    td ${Muted}, td ${Mono} {
        line-height: inherit;
    }
    tbody tr td {
        border-bottom: 1px solid ${variables.borderColor};
        padding-top: 5px;
        padding-bottom: 5px;
    }
    tbody tr:nth-child(even) td {
        background: ${variables.backgroundColorSection};
    }
`;

export const Row = styled.div`
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    align-items: ${(props) => props.align || 'flex-start'};
`;

export const Box = styled.div`
    flex: ${(props) => props.flex || '1 1 320px'};
    min-width: 0;
    border: 1px solid ${variables.borderColorWeak};
    background: ${variables.backgroundColorSection};
    padding: 10px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
`;

export const H = styled.div`
    font-weight: 600;
    font-size: 14px;
`;

export const Code = styled.code`
    display: block;
    font-family: ${variables.monoFontFamily};
    font-size: 12px;
    background: ${variables.backgroundColorPage};
    border: 1px solid ${variables.borderColorWeak};
    padding: 5px 8px;
    white-space: pre-wrap;
    word-break: break-all;
    user-select: all;
`;

export const Kpi = styled.div`
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 120px;
    b {
        font-size: 22px;
        font-weight: 600;
        line-height: 1.2;
    }
`;

const BarTrack = styled.span`
    display: inline-block;
    width: ${(props) => props.width}px;
    height: 8px;
    vertical-align: middle;
    margin-right: 6px;
    background: ${variables.backgroundColorPage};
    border: 1px solid ${variables.borderColorWeak};
    box-sizing: border-box;
`;

const BarFill = styled.span`
    display: block;
    height: 100%;
    width: ${(props) => props.pct}%;
    background: ${variables.contentColorMuted};
`;

export function Bar({ ratio, width = 80 }) {
    const value = Math.max(0, Math.min(1, Number(ratio) || 0));
    return (
        <BarTrack width={width} aria-hidden="true">
            <BarFill pct={value * 100} />
        </BarTrack>
    );
}

export const NoWrap = styled.span`
    white-space: nowrap;
`;

export const Tags = styled.div`
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
    align-items: center;
`;
