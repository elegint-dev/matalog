const fs = require('fs');
const path = require('path');
const { merge: webpackMerge } = require('webpack-merge');
const baseConfig = require('@splunk/webpack-configs/base.config').default;

// One entry per directory under src/pages; each becomes a self-contained appserver/static/pages/<page>.js,
// the one script Splunk's built-in pages/splunk_ui_app.html template loads for the view of the same name.
const pagesDir = path.join(__dirname, 'src/pages');
const entries = fs
    .readdirSync(pagesDir)
    .filter((name) => !/^\./.test(name))
    .reduce((accum, page) => {
        accum[page] = path.join(pagesDir, page);
        return accum;
    }, {});

module.exports = webpackMerge(baseConfig, {
    entry: entries,
    output: {
        path: path.join(__dirname, '../appserver/static/pages'),
        filename: '[name].js',
        chunkFilename: '[name].js',
    },
    devtool: false,
});
