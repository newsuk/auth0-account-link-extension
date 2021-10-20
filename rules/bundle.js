/* eslint-disable no-console */
const fs = require('fs').promises;
const esbuild = require('esbuild');
const rules = require('../package.json')['auth0-rules'];
const path = require('path');

async function bundle(dependencies, script) {
  console.log(`Bundling '${script}/index.ts'...`);

  // build bundle
  const result = await esbuild.build({
    entryPoints: [path.resolve(__dirname, script, 'index.ts')],
    bundle: true,
    platform: 'node',
    external: Object.keys(dependencies),
    banner: { js: `function ${script}(user, context, callback){` },
    footer: { js: '\nreturn exports.default(user, context, callback);\n}' },
    target: 'node8',
    write: false
  });

  console.log(`Bundled '${script}/index.ts'. Saving to 'dist/${script}.js'...`);

  let outfile = Buffer.from(result.outputFiles[0].contents).toString('utf-8');

  // update the imported dependencies to include versions
  Object.entries(dependencies).forEach(([key, value]) => {
    if (value === 'native') { return; }
    outfile = outfile.replace(new RegExp(`require\\("${key}"\\)`, 'g'), `require("${key}@${value}")`);
  });

  await fs.writeFile(path.resolve(__dirname, 'dist', `${script}.js`), outfile);

  console.log(`Saved 'dist/${script}.js'`);
}

async function main() {
  console.log('Starting bundling of auth0 rules');

  await fs.mkdir(path.resolve(__dirname, 'dist'), { recursive: true });
  await Promise.all(
    Object.entries(rules).map(([script, { dependencies }]) => bundle(dependencies, script))
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

