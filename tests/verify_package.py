"""Basic static verification on any OS. No execution of Windows scripts."""
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
scripts=list((root/'scripts'/'controles').glob('*.ps1'))
assert len(scripts)==16, f'Expected 16 controls, got {len(scripts)}'
for i in range(1,17):
    matching=[p for p in scripts if p.name.startswith(f'{i:02d}-')]
    assert len(matching)==1, f'Control {i:02d} missing'
    code=matching[0].read_text('utf-8')
    for action in ('Get','Set','Test'):
        assert f'function {action}-HW{i:02d}State' in code
    assert code.count('{')==code.count('}'), f'Unbalanced curly braces: {matching[0].name}'
for p in root.rglob('*'):
    if p.suffix in ('.ps1','.psm1'):
        code=p.read_text('utf-8')
        assert not '\x00' in code, f'NUL in {p}'
        assert code.count('{')==code.count('}'), f'Unbalanced braces in {p}'
for p in (root/'scripts/config').glob('*.json'):
    json.loads(p.read_text('utf-8'))
a=json.loads((root/'scripts/config/aprovacoes.example.json').read_text('utf-8'))
assert len(a['Controls'])==16
assert not a['EnableMutations'] and not a['ConfirmedLab'], 'Mutation and lab flags must default to false'
assert not any(v['Enabled'] or v['RollbackEnabled'] for v in a['Controls'].values()), 'Approvals must default to false'
assert (root/'Main.ps1').exists()
assert not any((root/'output').rglob('results.json')), 'Runtime evidence should stay out of a clean package'
print(f'PASS - {len(scripts)} controls, Main.ps1, JSON config, approvals off, no packaged runtime evidence')
