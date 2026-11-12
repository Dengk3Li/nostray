import test from 'node:test';
import assert from 'node:assert/strict';
import { compareCodeExports, scanPythonExports } from '../src/code-scanner.mjs';

test('Python zero-argument model eval is distinct from dynamic evaluation', () => {
  for (const call of ['model.eval()', 'model . eval ()', 'self.model.eval( )']) {
    const before = `def infer(model):\n    ${call}\n    return 1\n\ndef sibling():\n    return 3\n`;
    assert.equal(compareCodeExports(before, before.replace('return 1', 'return 2'), 'model.py').ok, true, call);
    assert.equal(compareCodeExports(before, before.replace('\ndef sibling():\n    return 3\n', ''), 'model.py').code, 'PUBLIC_EXPORT_MUTATED');
  }
  for (const call of ['eval("code")', 'eval()', 'builtins.eval("code")', 'builtins . eval()', '__builtins__.eval()', 'model.eval("code")', 'globals()', 'setattr(model, "x", 1)']) {
    assert.equal(scanPythonExports(`def infer(model):\n    ${call}\n`).verdict, 'UNKNOWN', call);
  }
  for (const source of ['import builtins as b\ndef infer():\n    b.eval("code")\n', 'import builtins\nb = builtins\ndef infer():\n    b.eval("code")\n']) assert.equal(scanPythonExports(source).verdict, 'UNKNOWN');
});

test('Imported known Python decorators retain their provider and exact wrapper contract', () => {
  for (const [provider, decorator] of [
    ['import torch', '@torch.no_grad()'],
    ['from torch import no_grad as ng', '@ng()'],
    ['import contextlib', '@contextlib.contextmanager'],
  ]) {
    const before = `${provider}\n${decorator}\ndef infer(x):\n    return x\n\ndef sibling():\n    return 1\n`;
    assert.equal(compareCodeExports(before, before.replace('return x', 'return x + 1'), 'model.py').ok, true, decorator);
    assert.equal(compareCodeExports(before, before.replace(`${decorator}\n`, ''), 'model.py').code, 'PUBLIC_EXPORT_MUTATED');
    assert.equal(compareCodeExports(before, before.replace('infer(x)', 'infer(x, y)'), 'model.py').code, 'PUBLIC_EXPORT_MUTATED');
    assert.equal(compareCodeExports(before, before.replace('\ndef sibling():\n    return 1\n', ''), 'model.py').code, 'PUBLIC_EXPORT_MUTATED');
  }
  for (const source of [
    '@torch.no_grad()\ndef f():\n    return 1\n',
    'import evil as torch\n@torch.no_grad()\ndef f():\n    return 1\n',
    'import torch\ntorch = evil\n@torch.no_grad()\ndef f():\n    return 1\n',
    'import torch\n@torch.no_grad(dynamic())\ndef f():\n    return 1\n',
    'import torch\nclass C:\n    torch = evil\n    @torch.no_grad()\n    def f(self):\n        return 1\n',
  ]) assert.equal(scanPythonExports(source).verdict, 'UNKNOWN', source);
});

test('Dataclass field order, private fields, defaults, annotations and flags form the contract', () => {
  const before = [
    'import dataclasses',
    '@dataclasses.dataclass(frozen=True)',
    'class Result:',
    '    x: int',
    '    _secret: str = "a"',
    '    scale: float = 1.0',
    '    def value(self):',
    '        return self.scale',
    '',
  ].join('\n');
  assert.equal(compareCodeExports(before, before.replace('return self.scale', 'return self.scale * 2'), 'data.py').ok, true);
  for (const after of [
    before.replace('    x: int\n', ''),
    before.replace('x: int', 'x: float'),
    before.replace('"a"', '"b"'),
    before.replace('scale: float = 1.0', 'scale: float = 2.0'),
    before.replace('    x: int\n    _secret: str = "a"', '    _secret: str = "a"\n    x: int'),
    before.replace('frozen=True', 'frozen=False'),
  ]) assert.equal(compareCodeExports(before, after, 'data.py').code, 'PUBLIC_EXPORT_MUTATED', after);
  const aliased = before.replace('import dataclasses', 'from dataclasses import dataclass as dc').replace('@dataclasses.dataclass', '@dc');
  assert.equal(scanPythonExports(aliased).verdict, 'OK');
  const privateDefault = 'import dataclasses\n_DEFAULT = 1\n@dataclasses.dataclass\nclass Result:\n    x: int = _DEFAULT\n';
  assert.equal(compareCodeExports(privateDefault, privateDefault.replace('_DEFAULT = 1', '_DEFAULT = 2'), 'data.py').code, 'PUBLIC_EXPORT_MUTATED');
  const importedType = 'from dataclasses import dataclass\nfrom builtins import int as T\n@dataclass\nclass Result:\n    x: T\n';
  assert.equal(compareCodeExports(importedType, importedType.replace('int as T', 'str as T'), 'data.py').code, 'PUBLIC_EXPORT_MUTATED');
  const stringType = importedType.replace('x: T', 'x: "T"');
  assert.equal(compareCodeExports(stringType, stringType.replace('int as T', 'str as T'), 'data.py').code, 'PUBLIC_EXPORT_MUTATED');
  const transitiveDefault = privateDefault.replace('_DEFAULT = 1', '_BASE = 1\n_DEFAULT = _BASE + 1');
  assert.equal(compareCodeExports(transitiveDefault, transitiveDefault.replace('_BASE = 1', '_BASE = 2'), 'data.py').code, 'PUBLIC_EXPORT_MUTATED');
  const transitiveType = importedType.replace('@dataclass', '_ALIAS = list[T]\n@dataclass').replace('x: T', 'x: _ALIAS');
  assert.equal(compareCodeExports(transitiveType, transitiveType.replace('int as T', 'str as T'), 'data.py').code, 'PUBLIC_EXPORT_MUTATED');
  for (const source of [
    before.replace('frozen=True', 'frozen=dynamic()'),
    before.replace('frozen=True', 'frozen=True, frozen=False'),
    before.replace('class Result:', 'class Result(Base):'),
    before.replace('    x: int', '    if enabled:\n        x: int'),
    before.replace('    x: int', '    x: int\n    x: float'),
  ]) assert.equal(scanPythonExports(source).verdict, 'UNKNOWN', source);
});

test('Python public method decorators retain signatures and reject shadowed bindings', () => {
  const before = 'import torch\nclass Model:\n    @torch.no_grad()\n    def infer(self, x):\n        return x\n';
  assert.equal(compareCodeExports(before, before.replace('return x', 'return x + 1'), 'model.py').ok, true);
  assert.equal(compareCodeExports(before, before.replace('    @torch.no_grad()\n', ''), 'model.py').code, 'PUBLIC_EXPORT_MUTATED');
  assert.equal(scanPythonExports('staticmethod = custom\nclass Model:\n    @staticmethod\n    def f():\n        return 1\n').verdict, 'UNKNOWN');
  assert.equal(scanPythonExports('class Model:\n    @property()\n    def f(self):\n        return 1\n').verdict, 'UNKNOWN');
  for (const statement of ['torch, other = evil, 1', 'if enabled:\n        torch = evil', 'torch.no_grad = evil', 'import evil as torch']) {
    assert.equal(scanPythonExports(before.replace('class Model:', `class Model:\n    ${statement}`)).verdict, 'UNKNOWN', statement);
  }
});
