import React from 'react';
import layout from '@splunk/react-page/18';
import { getThemeOptions, getUserTheme } from '@splunk/splunk-utils/themes';
import Status from './Status';

getUserTheme().then((name) => {
    const t = getThemeOptions(name);
    layout(<Status />, { pageTitle: 'Status', theme: t.colorScheme, themeFamily: t.family });
});
