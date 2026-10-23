#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const solc = require('solc');

const root = path.resolve(__dirname, '..');
const configPath = path.join(root, 'solc.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const expectedVersion = config.compiler.replace('solc@', '');

if (!solc.version().startsWith(`${expectedVersion}+`)) {
  throw new Error(`Expected solc ${expectedVersion}, received ${solc.version()}`);
}

const contractDir = path.join(root, 'contracts');
const sources = {};
for (const filename of fs.readdirSync(contractDir).filter((name) => name.endsWith('.sol')).sort()) {
  const sourceName = `contracts/${filename}`;
  sources[sourceName] = {
    content: fs.readFileSync(path.join(contractDir, filename), 'utf8')
  };
}

function findImports(importPath) {
  const candidates = [
    path.join(root, 'node_modules', importPath),
    path.join(contractDir, importPath)
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return { contents: fs.readFileSync(candidate, 'utf8') };
    }
  }
  return { error: `Import not found: ${importPath}` };
}

const output = JSON.parse(solc.compile(JSON.stringify({
  language: 'Solidity',
  sources,
  settings: config.settings
}), { import: findImports }));

const errors = output.errors || [];
for (const diagnostic of errors) {
  console.error(diagnostic.formattedMessage.trim());
}
if (errors.some((diagnostic) => diagnostic.severity === 'error')) {
  process.exitCode = 1;
  return;
}

const compiled = output.contracts?.['contracts/TPALedger.sol']?.TPALedger;
if (!compiled?.evm?.bytecode?.object) {
  throw new Error('TPALedger artifact was not generated');
}

const buildDir = path.join(root, 'build');
fs.mkdirSync(buildDir, { recursive: true });
const artifact = {
  contractName: 'TPALedger',
  compiler: solc.version(),
  evmVersion: config.settings.evmVersion,
  abi: compiled.abi,
  bytecode: `0x${compiled.evm.bytecode.object}`,
  deployedBytecode: `0x${compiled.evm.deployedBytecode.object}`
};
fs.writeFileSync(path.join(buildDir, 'TPALedger.json'), `${JSON.stringify(artifact, null, 2)}\n`);
console.log(`Compiled TPALedger with solc ${artifact.compiler} (evmVersion: ${artifact.evmVersion})`);
