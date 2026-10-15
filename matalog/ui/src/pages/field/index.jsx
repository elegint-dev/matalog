import React from 'react';
import layout from '@splunk/react-page/18';
import { getThemeOptions, getUserTheme } from '@splunk/splunk-utils/themes';
import Field from './Field';

getUserTheme().then((name) => {
    const t = getThemeOptions(name);
    layout(<Field />, { pageTitle: 'Field', theme: t.colorScheme, themeFamily: t.family });
});
