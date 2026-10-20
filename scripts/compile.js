import solc from 'solc';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
const input = {
  language: 'Solidity',
  sources: { 'FileRegistry.sol': { content: readFileSync('contracts/FileRegistry.sol', 'utf8') } },
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'paris',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
for (const e of output.errors || []) console.error(e.formattedMessage);
if (output.errors?.some(e => e.severity === 'error')) process.exit(1);
mkdirSync('artifacts', { recursive: true });
writeFileSync('artifacts/FileRegistry.json', JSON.stringify(output.contracts['FileRegistry.sol'].FileRegistry, null, 2));
console.log('Compiled FileRegistry using pinned local solc 0.8.28.');
