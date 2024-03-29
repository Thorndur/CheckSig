
const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    index: "./js/index.js",
    signature: "./js/signature.js"
  },
  output: {
    path: dist,
    filename: "[name].js"
  },
  devServer: {
    contentBase: dist,
  },

  plugins: [
    new CopyPlugin({
      patterns: [
        {from: path.resolve(__dirname, "static")},
        {from: path.resolve(__dirname, "js")}
      ]
    }),

    new WasmPackPlugin({
      crateDirectory: __dirname
    }),
  ]
};
