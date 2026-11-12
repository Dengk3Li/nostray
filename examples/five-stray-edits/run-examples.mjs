import { runInteractiveDemo } from '../../src/demo-runner.mjs';
const result = await runInteractiveDemo();
if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
else for (const item of result.results) console.log(`\n${item.id}: ${item.status} (${item.code})\nBefore:\n${item.before}\nAttempted:\n${item.after}\n`);
if (!result.passed) process.exitCode = 1;
