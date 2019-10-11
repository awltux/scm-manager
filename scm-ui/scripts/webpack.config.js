const path = require("path");
const createIndexMiddleware = require("./IndexMiddleware");
const createContextPathMiddleware = require("./ContextPathMiddleware");

module.exports = [{
  context: path.resolve(__dirname, ".."),
  entry: {
    webapp: [
      "./ui-webapp/src/webpack-public-path.js",
      "./ui-styles/src/scm.scss",
      "./ui-webapp/src/index.js"
    ]
  },
  devtool: "cheap-module-eval-source-map",
  target: "web",
  node: {
    fs: "empty",
    net: "empty",
    tls: "empty"
  },
  module: {
    rules: [
      {
        parser: {
          system: false,
          systemjs: false
        }
      },
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: [
          {
            loader: "cache-loader"
          },
          {
            loader: "thread-loader"
          },
          {
            loader: "babel-loader",
            options: {
              cacheDirectory: true,
              presets: [
                "@scm-manager/babel-preset"
              ]
            }
          }
        ]
      },
      {
        test: /\.(css|scss|sass)$/i,
        use: [
          // Creates `style` nodes from JS strings
          "style-loader",
          // Translates CSS into CommonJS
          "css-loader",
          // Compiles Sass to CSS
          "sass-loader"
        ]
      },
      {
        test: /\.(png|svg|jpg|gif|woff2?|eot|ttf)$/,
        use: ["file-loader"]
      }
    ]
  },
  output: {
    path: path.resolve(__dirname, "..", "target", "assets"),
    filename: "[name].bundle.js"
  },
  devServer: {
    contentBase: path.join(__dirname, "..", "ui-webapp", "public"),
    compress: false,
    historyApiFallback: true,
    overlay: true,
    port: 3000,
    before: function(app) {
      app.use(createContextPathMiddleware("/scm"));
    },
    after: function(app) {
      const templatePath = path.join(
        __dirname,
        "..",
        "ui-webapp",
        "public",
        "index.mustache"
      );
      const renderParams = {
        contextPath: "/scm"
      };
      app.use(createIndexMiddleware(templatePath, renderParams));
    },
    publicPath: "/assets/"
  },
  optimization: {
    runtimeChunk: "single",
    splitChunks: {
      chunks: "all",
      cacheGroups: {
        vendors: {
          test: /[\\/]node_modules[\\/]/,
          priority: -10,
          // chunks: chunk => chunk.name !== "polyfill"
        },
        default: {
          minChunks: 2,
          priority: -20,
          reuseExistingChunk: true
        }
      }
    }
  }
}, {
  context: path.resolve(__dirname, ".."),
  entry: {
    polyfill: "./ui-polyfill/src/index.js"
  },
  output: {
    path: path.resolve(__dirname, "..", "target", "assets"),
    filename: "[name].bundle.js"
  }
}];
