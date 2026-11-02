#!/usr/bin/env python3
"""OpenLine Agent Hunt Lab: retrospective, unsigned, fictional tool-event triage.

Not an OpenLine enforcement engine. No live agent interception or signed verification.
"""
import argparse
import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def find_allowed(agent, tool, resource):
    # Exact resource matching only. No path-prefix authorization shortcuts.
    return any(item['tool'] == tool and item['resource'] == resource for item in agent.get('permissions', []))


def classify_event(event, policy, seen_nonces):
    agent = policy['agents'].get(event['agent'], None)
    reasons = []
    if agent is None:
        reasons.append('UNKNOWN_AGENT')
    else:
        if agent.get('revoked_at') and parse_time(event['time']) >= parse_time(agent['revoked_at']):
            reasons.append('REVOKED_IDENTITY')
        if not find_allowed(agent, event['tool'], event['resource']):
            reasons.append('OUT_OF_SCOPE')
        if event.get('evidence'):
            evidence = policy.get('evidence', {}).get(event['evidence'])
            if evidence is None or evidence.get('status') != 'valid':
                reasons.append('STALE_OR_MISSING_EVIDENCE')
    nonce = (event['agent'], event.get('nonce'))
    if event.get('nonce') and nonce in seen_nonces:
        reasons.append('REPEATED_NONCE')
    if event.get('nonce'):
        seen_nonces.add(nonce)
    status = 'SCOPE_ALERT' if reasons else 'IN_SCOPE_REQUEST'
    # These are log claims, not receiver-verified execution receipts.
    return {
        'id': event['id'], 'time': event['time'], 'agent': event['agent'],
        'tool': event['tool'], 'resource': event['resource'],
        'status': status, 'reasons': reasons,
        'effect_claim': event.get('effect_claim', 'unknown'),
        'effect_truth': 'UNKNOWN — source events are unsigned and not receiver-verified',
    }


def assess_impact(policy):
    result=[]
    evidence=policy.get('evidence', {})
    for obj in policy.get('work', []):
        if not obj.get('complete_dependencies', False):
            status='UNDETERMINED'
        elif any(evidence.get(dep, {}).get('status') != 'valid' for dep in obj.get('dependencies', [])):
            status='REOPEN'
        else:
            status='RETAIN'
        result.append({'name': obj['name'], 'status': status,
                       'dependencies': obj.get('dependencies', []),
                       'basis': 'declared demo dependencies only; not signed standing'})
    return result


def hunt(policy, events):
    seen=set()
    findings=[classify_event(e, policy, seen) for e in sorted(events, key=lambda x:(x['time'], x['id']))]
    alerts=sum(f['status']=='SCOPE_ALERT' for f in findings)
    agents=sorted({f['agent'] for f in findings if f['status']=='SCOPE_ALERT'})
    return {'kind':'OPENLINE_AGENT_HUNT_LAB_SIMULATION', 'source_authenticity':'UNVERIFIED',
            'enforcement':'NONE — retrospective inspection only',
            'observed_events':len(findings),'scope_alert_events':alerts,
            'flagged_agents':agents,'findings':findings,'impact':assess_impact(policy),
            'disclaimer':'A scope alert is not proof of malicious intent or that an action executed. Receiver-signed decisions and effect records are not connected in this standalone lab.'}


def build_html(report):
    safe_json=json.dumps(report, ensure_ascii=False).replace('</','<\\/')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenLine Agent Hunt Lab · Offline Incident Console</title>
<style>
:root{color-scheme:dark;--bg:#0b1019;--ink:#edf3fa;--muted:#a4b4c5;--line:#2b384b;--panel:#151f2e;--blue:#8dc3ff;--red:#ff9b96;--amber:#ffd091;--green:#91e0bc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}
main{max-width:1100px;margin:auto;padding:30px 18px 70px}h1{font-size:clamp(28px,5vw,46px);line-height:1.1;margin:12px 0}h2{font-size:19px;margin:28px 0 12px}p{color:var(--muted)}.eyebrow{letter-spacing:.14em;text-transform:uppercase;color:var(--blue);font-weight:700;font-size:11px}.banner{border:1px solid #725c3d;background:#2c2418;color:#ffdfa8;border-radius:10px;padding:12px 14px;margin:20px 0}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:16px}.stat strong{font-size:30px;display:block;line-height:1.3}.stat small{color:var(--muted)}.panel{margin-top:12px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}button{background:#1e2a3b;color:var(--ink);border:1px solid #45566c;border-radius:8px;padding:9px 13px;cursor:pointer;font:inherit}button.active{background:#d5e7ff;color:#112036}.event{padding:13px 0;border-bottom:1px solid var(--line)}.event:last-child{border:0}.head{display:flex;flex-wrap:wrap;align-items:center;gap:9px}.label{font-size:11px;font-weight:700;border-radius:6px;padding:3px 7px;background:#31435b;color:var(--blue)}.label.alert{background:#4e2528;color:var(--red)}.label.reopen{background:#54371b;color:var(--amber)}.label.retain{background:#153e32;color:var(--green)}.label.undetermined{background:#3c344a;color:#d2baff}.item-title{font-weight:700}.detail{color:var(--muted);font-size:13px;margin:5px 0 0;overflow-wrap:anywhere}.issues{color:var(--red)}.impact{padding:13px 0;border-bottom:1px solid var(--line)}.impact:last-child{border:0}code{color:#c2e0ff}.foot{font-size:12px;color:var(--muted)}@media(max-width:660px){.grid{grid-template-columns:repeat(2,1fr)}.stat strong{font-size:26px}}
</style></head><body><main>
<div class="eyebrow">OPENLINE · OFFLINE CONCEPT DEMONSTRATION</div>
<h1>Agent Hunt Lab</h1><p>Which agent went outside its assignment? What do we actually know? Which accepted work should be reconsidered?</p>
<div class="banner"><strong>SIMULATION, NOT ACTIVE PROTECTION.</strong> This page reads fictional, unsigned tool-event logs. No real agent is intercepted, no authorization is enforced, and no external effect is verified.</div>
<section class="grid"><div class="stat"><strong id="events"></strong><small>Logged requests</small></div><div class="stat"><strong id="alerts"></strong><small>Scope alerts</small></div><div class="stat"><strong id="agents"></strong><small>Flagged agents</small></div><div class="stat"><strong id="reopen"></strong><small>Work to revisit</small></div></section>
<h2>Investigation feed</h2><p>A scope alert is an observable mismatch against declared permissions, not a claim about an agent's intentions.</p>
<div class="toolbar"><button class="active" data-filter="all">All events</button><button data-filter="alert">Scope alerts</button><button data-filter="normal">In-scope</button></div>
<section class="panel" id="feed"></section>
<h2>What downstream work changed?</h2><p>Based on explicitly declared dependencies. Incomplete capture stays unknown.</p><section class="panel" id="impact"></section>
<h2>What would make this a real OpenLine product?</h2><section class="panel"><p><strong>Instrument the execution boundary</strong> and accept only independently verified receiver-signed receipts. Feed actual source standing to <code>openline-impact</code>. Link verified effects, revocations, owner assignments, and successor recovery. Then compare against existing agent-security tools on the same unseen incidents.</p><p><strong>Falsifiers:</strong> an unauthorized action that reaches the real effect; a legitimate action wrongly stopped; a missing event falsely classified as safe; a downstream dependency missed; or a forged log accepted as proof.</p></section>
<p class="foot">Privacy: one offline file, no analytics, no external network calls. All sample names, events, and effects are fictional. Generated by hunt.py.</p>
</main><script type="application/json" id="report-data">'''+safe_json+'''</script><script>
const d=JSON.parse(document.getElementById('report-data').textContent),$=id=>document.getElementById(id);
$('events').textContent=d.observed_events;$('alerts').textContent=d.scope_alert_events;$('agents').textContent=d.flagged_agents.length;$('reopen').textContent=d.impact.filter(x=>x.status==='REOPEN').length;
function elem(tag,className,text){const e=document.createElement(tag);if(className)e.className=className;if(text!==undefined)e.textContent=text;return e}
function draw(filter){$('feed').replaceChildren();for(const f of d.findings){const alert=f.status==='SCOPE_ALERT';if(filter==='alert'&&!alert||filter==='normal'&&alert)continue;
const e=elem('article','event'),h=elem('div','head');h.append(elem('span','label'+(alert?' alert':''),alert?'SCOPE ALERT':'IN SCOPE'),elem('span','item-title',f.agent+' · '+f.tool));e.append(h,elem('div','detail',f.time+' · '+f.resource));
if(alert)e.append(elem('div','detail issues','Why flagged: '+f.reasons.join(', ')));e.append(elem('div','detail','Effect: UNKNOWN (unverified log claim: '+f.effect_claim+')'));$('feed').append(e)} }
for(const b of document.querySelectorAll('button[data-filter]'))b.addEventListener('click',()=>{for(const x of document.querySelectorAll('button'))x.classList.remove('active');b.classList.add('active');draw(b.dataset.filter)});draw('all');
for(const x of d.impact){const e=elem('div','impact'),h=elem('div','head');h.append(elem('span','label '+x.status.toLowerCase(),x.status),elem('span','item-title',x.name));e.append(h,elem('div','detail','Declared evidence: '+(x.dependencies.join(', ')||'none')));$('impact').append(e)}
</script></body></html>'''


def main():
    p=argparse.ArgumentParser(description='Offline retrospective agent-log hunt; not a live firewall')
    p.add_argument('--policy', type=Path, default=Path(__file__).with_name('policy.json'))
    p.add_argument('--events', type=Path, default=Path(__file__).with_name('events.jsonl'))
    p.add_argument('--html', type=Path, default=Path('hunt-report.html'))
    p.add_argument('--json', type=Path, default=Path('hunt-report.json'))
    a=p.parse_args()
    policy=json.loads(a.policy.read_text(encoding='utf-8'))
    events=[json.loads(x) for x in a.events.read_text(encoding='utf-8').splitlines() if x.strip()]
    report=hunt(policy,events)
    a.html.write_text(build_html(report),encoding='utf-8')
    a.json.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(f"{report['observed_events']} fictional tool events; {report['scope_alert_events']} scope alerts; {len(report['flagged_agents'])} flagged agents; {sum(x['status']=='REOPEN' for x in report['impact'])} REOPEN")
    print('No execution claims were verified. Reports:',a.html,a.json)


if __name__=='__main__':
    main()
