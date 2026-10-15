// A copyable search fragment: the text in a code block plus a copy button.
import React, { useState } from 'react';
import Button from '@splunk/react-ui/Button';
import { Code, Row } from './styles';

export default function Fragment({ spl }) {
    const [copied, setCopied] = useState(false);
    const copy = () => {
        const done = () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(spl).then(done, () => {});
        } else {
            const area = document.createElement('textarea');
            area.value = spl;
            document.body.appendChild(area);
            area.select();
            document.execCommand('copy');
            document.body.removeChild(area);
            done();
        }
    };
    return (
        <Row align="center" style={{ gap: 6, flexWrap: 'nowrap' }}>
            <Code style={{ flex: 1 }}>{spl}</Code>
            <Button appearance="secondary" label={copied ? 'copied' : 'copy'} onClick={copy} />
        </Row>
    );
}
