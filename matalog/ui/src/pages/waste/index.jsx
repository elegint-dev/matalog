import React from 'react';
import layout from '@splunk/react-page/18';
import { getThemeOptions, getUserTheme } from '@splunk/splunk-utils/themes';
import Waste from './Waste';

getUserTheme().then((name) => {
    const t = getThemeOptions(name);
    layout(<Waste />, { pageTitle: 'Waste', theme: t.colorScheme, themeFamily: t.family });
});
