const path = require('path');

module.exports = function override(config) {
  config.ignoreWarnings = [
    {
      module: /plotly\.js/,
      message: /Failed to parse source map/,
    },
  ];
  
  return config;
};