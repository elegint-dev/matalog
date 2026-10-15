import React from 'react';
import layout from '@splunk/react-page/18';
import { getThemeOptions, getUserTheme } from '@splunk/splunk-utils/themes';
import Lookup from './Lookup';

getUserTheme().then((name) => {
    const t = getThemeOptions(name);
    layout(<Lookup />, { pageTitle: 'Lookup', theme: t.colorScheme, themeFamily: t.family });
});
