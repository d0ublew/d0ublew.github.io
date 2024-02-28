```sh
git clone https://github.com/highlightjs/highlight.js
cd highlight.js
git checkout 10.7.3
npm install
node tools/build.js $(tr "\n" " " < languages.txt)
ls build/highlight.min.js
```
