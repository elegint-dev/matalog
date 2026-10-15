// Loading and error states every page shows the same way.
import React from 'react';
import Message from '@splunk/react-ui/Message';
import WaitSpinner from '@splunk/react-ui/WaitSpinner';
import { Muted } from './styles';

export function Loading({ what }) {
    return (
        <div>
            <WaitSpinner size="small" /> <Muted>{what || 'loading'}</Muted>
        </div>
    );
}

export function Failure({ error }) {
    if (!error) return null;
    return <Message type="error">{String(error.message || error)}</Message>;
}
