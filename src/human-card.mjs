export function detectPreferredLang(options = {}) {
  const requested = options.lang || process.env.NOSTRA_LANG || process.env.BLAST_GUARD_LANG;
  if (requested) return String(requested).toLowerCase().startsWith('zh') ? 'zh' : 'en';
  if (/[\u3400-\u9fff]/u.test(options.taskPrompt || '')) return 'zh';
  return /^zh/i.test(process.env.LANG || '') ? 'zh' : 'en';
}

export function formatHumanInterceptionCard(violations = [], context = {}) {
  const p = violations[0] || { code: 'SCOPE_VIOLATION', path: '<unknown>' };
  const zh = detectPreferredLang(context) === 'zh';
  const messages = {
    PUBLIC_EXPORT_MUTATED: ['change or remove a public export', '修改或删除公开导出'],
    TEST_SETUP_OR_BODY_MUTATED: ['change an existing test', '修改现有测试'],
    RING0_CONTRACT_LOCKED: ['change a protected contract', '修改受保护的契约'],
    JSON_SCHEMA_CONSTRAINT_MUTATED: ['change a protected schema constraint', '修改受保护的数据约束'],
    DOC_NUMERIC_OR_EPISTEMIC_DRIFT: ['change a protected number or qualification', '修改受保护的数字或限定表述'],
    BUDGET_LINE_WIPE_EXCEEDED: ['remove more lines than the task permits', '删除的行数超过本次任务范围'],
  };
  const action = messages[p.code]?.[zh ? 1 : 0] || (zh ? '修改受保护的内容' : 'change protected content');
  const file = String(p.path || '<unknown>').replace(/[\r\n]/g, ' ');
  const impact = context.callerImpact;
  const task = context.taskPrompt || (zh ? '（当前会话）' : '(current session)');
  return zh ? [
    '✋ NoStray 拦下了一次越界修改', `当前任务：${task}`, `尝试操作：${action}：${file}`,
    `影响范围：${impact?.transitiveCallers ? `${impact.directCallers} 个直接调用方，${impact.transitiveCallers} 个间接调用方` : '受保护的契约或测试'}`,
    '可选操作：', '[1] 将修改限制在目标实现文件中（推荐）',
    `[2] 为当前任务明确授权：nostray session start --prompt "Allow updating ${file}: <your task>"`,
    '[3] 查看差异和时间线：nostray ui；或恢复工作区：nostray rollback --recover',
  ].join('\n') : [
    '✋ NoStray blocked a stray edit', `Task: ${task}`, `Attempted: ${action}: ${file}`,
    `Impact: ${impact?.transitiveCallers ? `${impact.directCallers} direct and ${impact.transitiveCallers} transitive callers` : 'protected contracts or tests'}`,
    'Options:', '[1] Keep changes inside target implementation files (recommended)',
    `[2] Authorize this file for the task: nostray session start --prompt "Allow updating ${file}: <your task>"`,
    '[3] Open the diff and timeline: nostray ui; or recover: nostray rollback --recover',
  ].join('\n');
}
