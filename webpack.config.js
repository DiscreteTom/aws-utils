import path from "path";
const __dirname = path.resolve();

export default {
  entry: "./browser.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bundle.js",
  },
};
